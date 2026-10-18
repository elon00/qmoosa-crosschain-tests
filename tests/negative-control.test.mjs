import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  computeHashlock,
  verifyPreimage,
  computeSwapId,
  verifyTimelockSafety
} from "@qmoosa/crosschain-protocol";
import {
  CrossChainEngine,
  AdminAuthManager,
  CrossChainSwapState
} from "@qmoosa/crosschain-engine";
import {
  CrossChainClient,
  generateSecretAndCommitment,
  SwapLifecycleState
} from "@qmoosa/crosschain-sdk";

const ONE_ETHER = 10n ** 18n;

test("Negative Control 1: Invalid secret preimage fails hashlock verification", () => {
  const { publicKey: adminPub } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);
  const client = new CrossChainClient(12, 32);

  const { secret, hashlock } = client.createSecretCommitment();
  const swapId = "0x" + "11".repeat(32);

  engine.createSwapOrder({
    swapId,
    sender: "0xAlice",
    recipient: "0xBob",
    sourceToken: "0xTokenA",
    destToken: "0xTokenB",
    sourceAmount: 100n * ONE_ETHER,
    destAmount: 100n * ONE_ETHER,
    hashlock,
    sourceTimelock: 10600,
    destTimelock: 10200,
    sourceChainId: 1,
    destChainId: 137,
    nonce: 1
  });

  engine.recordSourceFunding(swapId, 12);
  engine.recordCounterpartyFunding(swapId, 32);

  const bogusSecret = "0x" + "00".repeat(32);
  assert.throws(
    () => engine.revealSecretAndClaim(swapId, bogusSecret, 9500),
    /INVALID_SECRET_PREIMAGE/
  );
});

test("Negative Control 2: Premature refund before timelock expiry is rejected", () => {
  const { publicKey: adminPub } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);
  const client = new CrossChainClient(12, 32);

  const { hashlock } = client.createSecretCommitment();
  const swapId = "0x" + "22".repeat(32);

  engine.createSwapOrder({
    swapId,
    sender: "0xAlice",
    recipient: "0xBob",
    sourceToken: "0xTokenA",
    destToken: "0xTokenB",
    sourceAmount: 100n * ONE_ETHER,
    destAmount: 100n * ONE_ETHER,
    hashlock,
    sourceTimelock: 10600,
    destTimelock: 10200,
    sourceChainId: 1,
    destChainId: 137,
    nonce: 2
  });

  // Attempt refund when currentTimestamp (9500) <= sourceTimelock (10600)
  assert.throws(
    () => engine.executeRefund(swapId, 9500),
    /TIMELOCK_ACTIVE/
  );
});

test("Negative Control 3: Post-claim refund attack fails (Mutual Exclusion)", () => {
  const { publicKey: adminPub } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);
  const client = new CrossChainClient(12, 32);

  const { secret, hashlock } = client.createSecretCommitment();
  const swapId = "0x" + "33".repeat(32);

  engine.createSwapOrder({
    swapId,
    sender: "0xAlice",
    recipient: "0xBob",
    sourceToken: "0xTokenA",
    destToken: "0xTokenB",
    sourceAmount: 100n * ONE_ETHER,
    destAmount: 100n * ONE_ETHER,
    hashlock,
    sourceTimelock: 10600,
    destTimelock: 10200,
    sourceChainId: 1,
    destChainId: 137,
    nonce: 3
  });

  engine.recordSourceFunding(swapId, 12);
  engine.recordCounterpartyFunding(swapId, 32);
  engine.revealSecretAndClaim(swapId, secret, 9500);

  // Even at t=12000 > 10600, refund MUST fail
  assert.throws(
    () => engine.executeRefund(swapId, 12000),
    /MUTUAL_EXCLUSION_VIOLATION/
  );
});

test("Negative Control 4: Post-refund claim attack fails (Mutual Exclusion)", () => {
  const { publicKey: adminPub } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);
  const client = new CrossChainClient(12, 32);

  const { secret, hashlock } = client.createSecretCommitment();
  const swapId = "0x" + "44".repeat(32);

  engine.createSwapOrder({
    swapId,
    sender: "0xAlice",
    recipient: "0xBob",
    sourceToken: "0xTokenA",
    destToken: "0xTokenB",
    sourceAmount: 100n * ONE_ETHER,
    destAmount: 100n * ONE_ETHER,
    hashlock,
    sourceTimelock: 10600,
    destTimelock: 10200,
    sourceChainId: 1,
    destChainId: 137,
    nonce: 4
  });

  // Legitimate refund past source timelock at t=11000
  engine.executeRefund(swapId, 11000);
  assert.equal(engine.getSwap(swapId)?.state, CrossChainSwapState.REFUNDED);

  // Recipient attempts to claim afterwards
  assert.throws(
    () => engine.revealSecretAndClaim(swapId, secret, 11050),
    /INVALID_STATE_TRANSITION/
  );
});

test("Negative Control 5: Forged admin intent is rejected", () => {
  const { publicKey: adminPub } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);

  const { publicKey: attackerPub, privateKey: attackerPriv } = AdminAuthManager.generateKeyPair();

  const intent = {
    action: "SET_PAUSED",
    nonce: 1,
    deadline: Math.floor(Date.now() / 1000) + 3600,
    chainId: 1,
    params: { paused: true }
  };

  const signature = AdminAuthManager.signIntent(intent, attackerPriv);

  // Fails because signerPublicKey does not match allowed admin
  assert.throws(
    () => engine.executeAdminIntent({ ...intent, signature, signerPublicKey: attackerPub }),
    /UNAUTHORIZED_SIGNER/
  );
});

test("Negative Control 6: Replay attack on admin intent nonce is rejected", () => {
  const { publicKey: adminPub, privateKey: adminPriv } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);

  const intent = {
    action: "SET_PAUSED",
    nonce: 99,
    deadline: Math.floor(Date.now() / 1000) + 3600,
    chainId: 1,
    params: { paused: true }
  };

  const signature = AdminAuthManager.signIntent(intent, adminPriv);
  const signedIntent = { ...intent, signature, signerPublicKey: adminPub };

  // First execution succeeds
  engine.executeAdminIntent(signedIntent);
  assert.equal(engine.isPaused(), true);

  // Second execution with same nonce fails
  assert.throws(
    () => engine.executeAdminIntent(signedIntent),
    /NONCE_REPLAY_ATTACK/
  );
});

test("Negative Control 7: Deep chain reorg demotes confirmation depth back to unconfirmed", () => {
  const { publicKey: adminPub } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);
  const client = new CrossChainClient(12, 32);

  const { hashlock } = client.createSecretCommitment();
  const swapId = "0x" + "77".repeat(32);

  engine.createSwapOrder({
    swapId,
    sender: "0xAlice",
    recipient: "0xBob",
    sourceToken: "0xTokenA",
    destToken: "0xTokenB",
    sourceAmount: 100n * ONE_ETHER,
    destAmount: 100n * ONE_ETHER,
    hashlock,
    sourceTimelock: 10600,
    destTimelock: 10200,
    sourceChainId: 1,
    destChainId: 137,
    nonce: 7
  });

  // Reaches required finality (12)
  engine.recordSourceFunding(swapId, 12);
  assert.equal(engine.getSwap(swapId)?.state, CrossChainSwapState.SOURCE_FUNDED);

  // Chain reorg of 5 blocks rolls source depth back to 7 (< 12)
  engine.handleReorgRollback(swapId, 1, 5);
  const reorged = engine.getSwap(swapId);
  assert.equal(reorged?.sourceBlockDepth, 7);
  assert.equal(reorged?.state, CrossChainSwapState.CREATED);
});

test("Negative Control 8: Insufficient timelock safety delta is rejected by Engine and SDK", () => {
  const { publicKey: adminPub } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);
  const client = new CrossChainClient(12, 32);

  const { hashlock } = client.createSecretCommitment();
  const swapId = "0x" + "88".repeat(32);

  // Delta is only 100s < 300s
  assert.throws(
    () => engine.createSwapOrder({
      swapId,
      sender: "0xAlice",
      recipient: "0xBob",
      sourceToken: "0xTokenA",
      destToken: "0xTokenB",
      sourceAmount: 100n * ONE_ETHER,
      destAmount: 100n * ONE_ETHER,
      hashlock,
      sourceTimelock: 10300,
      destTimelock: 10200, // 100s delta
      sourceChainId: 1,
      destChainId: 137,
      nonce: 8
    }),
    /INSUFFICIENT_TIMELOCK_DELTA/
  );

  // SDK also rejects
  const clientResult = client.initiateSwapOrder({
    initiator: "0xAlice",
    recipient: "0xBob",
    token: "0xTokenA",
    amount: 100n * ONE_ETHER,
    hashlock,
    sourceTimelock: 10300,
    destTimelock: 10200,
    sourceChainId: 1,
    destChainId: 137
  });
  assert.equal(clientResult.success, false);
  assert.match(clientResult.error ?? "", /INSUFFICIENT_TIMELOCK_DELTA/);
});

test("Negative Control 9: Claim after destination timelock has elapsed is rejected", () => {
  const { publicKey: adminPub } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);
  const client = new CrossChainClient(12, 32);

  const { secret, hashlock } = client.createSecretCommitment();
  const swapId = "0x" + "99".repeat(32);

  engine.createSwapOrder({
    swapId,
    sender: "0xAlice",
    recipient: "0xBob",
    sourceToken: "0xTokenA",
    destToken: "0xTokenB",
    sourceAmount: 100n * ONE_ETHER,
    destAmount: 100n * ONE_ETHER,
    hashlock,
    sourceTimelock: 10600,
    destTimelock: 10200,
    sourceChainId: 1,
    destChainId: 137,
    nonce: 9
  });

  engine.recordSourceFunding(swapId, 12);
  engine.recordCounterpartyFunding(swapId, 32);

  // Attempt claim at t=10201 > 10200
  assert.throws(
    () => engine.revealSecretAndClaim(swapId, secret, 10201),
    /SWAP_TIMELOCK_EXPIRED/
  );
});
