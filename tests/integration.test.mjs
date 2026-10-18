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
  verifySecretCommitment,
  SwapLifecycleState
} from "@qmoosa/crosschain-sdk";

const ONE_ETHER = 10n ** 18n;

test("Integration 1: Cross-Chain HTLC deterministic Swap ID & Preimage verification", () => {
  const alice = "0x1111111111111111111111111111111111111111";
  const bob = "0x2222222222222222222222222222222222222222";
  const token = "0x3333333333333333333333333333333333333333";
  const amount = 100n * ONE_ETHER;
  const rawSecret = "super-secret-atomic-swap-key-123456";
  const hashlock = computeHashlock(rawSecret);
  const timelock = 10500;
  const sourceChainId = 1;
  const destChainId = 137;
  const nonce = 1;

  const swapId = computeSwapId({
    sender: alice,
    recipient: bob,
    token,
    amount,
    hashlock,
    timelock,
    sourceChainId,
    destChainId,
    nonce
  });

  assert.match(swapId, /^0x[0-9a-f]{64}$/);
  assert.equal(verifyPreimage(rawSecret, hashlock), true);
  assert.equal(verifyPreimage("wrong-secret", hashlock), false);
});

test("Integration 2: Secret & commitment cryptographic binding across SDK and Protocol", () => {
  const { secret, hashlock } = generateSecretAndCommitment();

  // SDK verification
  assert.equal(verifySecretCommitment(secret, hashlock), true);
  assert.equal(verifySecretCommitment("0x1234", hashlock), false);

  // Protocol verification
  assert.equal(verifyPreimage(secret, hashlock), true);
});

test("Integration 3: Timelock safety margin validation across Protocol and SDK", () => {
  const client = new CrossChainClient(12, 32);

  const sourceTimelock = 10600;
  const destTimelock = 10200;
  const safetyMargin = 300;

  // Protocol validation
  const report = verifyTimelockSafety(sourceTimelock, destTimelock, safetyMargin);
  assert.equal(report.isValid, true);
  assert.equal(report.deltaSeconds, 400);

  // SDK validation
  assert.equal(client.validateTimelockSafety(sourceTimelock, destTimelock, safetyMargin), true);

  // Unsafe margin (delta = 50s < 300s)
  const unsafeReport = verifyTimelockSafety(10250, 10200, safetyMargin);
  assert.equal(unsafeReport.isValid, false);
  assert.equal(client.validateTimelockSafety(10250, 10200, safetyMargin), false);
});

test("Integration 4: End-to-end multi-repo dual-chain atomic swap and mutual claim", () => {
  const { publicKey: adminPub, privateKey: adminPriv } = AdminAuthManager.generateKeyPair();
  const engine = new CrossChainEngine(adminPub, 1);
  const client = new CrossChainClient(12, 32);

  const alice = "0xAlice1111111111111111111111111111111111";
  const bob = "0xBob2222222222222222222222222222222222222";
  const tokenA = "0xTokenA000000000000000000000000000000000";
  const tokenB = "0xTokenB000000000000000000000000000000000";

  // 1. Alice generates secret & hashlock using SDK
  const { secret, hashlock } = client.createSecretCommitment();

  const sourceTimelock = 10600;
  const destTimelock = 10200; // 400s delta >= 300s required buffer

  const swapId = computeSwapId({
    sender: alice,
    recipient: bob,
    token: tokenA,
    amount: 100n * ONE_ETHER,
    hashlock,
    timelock: sourceTimelock,
    sourceChainId: 1,
    destChainId: 137,
    nonce: 101
  });

  // 2. Engine registers swap order
  const order = engine.createSwapOrder({
    swapId,
    sender: alice,
    recipient: bob,
    sourceToken: tokenA,
    destToken: tokenB,
    sourceAmount: 100n * ONE_ETHER,
    destAmount: 250n * ONE_ETHER,
    hashlock,
    sourceTimelock,
    destTimelock,
    sourceChainId: 1,
    destChainId: 137,
    nonce: 101
  });

  assert.equal(order.state, CrossChainSwapState.CREATED);

  // 3. Alice funds source on Chain 1 (depth reaches 12 confirmations)
  engine.recordSourceFunding(swapId, 12);
  let currentSwap = engine.getSwap(swapId);
  assert.equal(currentSwap.state, CrossChainSwapState.SOURCE_FUNDED);

  // 4. Bob funds destination on Chain 137 (depth reaches 32 confirmations)
  engine.recordCounterpartyFunding(swapId, 32);
  currentSwap = engine.getSwap(swapId);
  assert.equal(currentSwap.state, CrossChainSwapState.CLAIMABLE);

  // 5. Alice reveals secret and claims on destination chain (before dest timelock)
  const claimedSwap = engine.revealSecretAndClaim(swapId, secret, 9500);
  assert.equal(claimedSwap.state, CrossChainSwapState.CLAIMED);
  assert.equal(claimedSwap.revealedSecret, secret);

  // 6. Mutual exclusion: Alice cannot refund after claim
  assert.throws(
    () => engine.executeRefund(swapId, 12000),
    /MUTUAL_EXCLUSION_VIOLATION/
  );
});
