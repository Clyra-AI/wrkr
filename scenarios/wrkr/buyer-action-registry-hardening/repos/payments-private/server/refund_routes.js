const router = require("express").Router();

router.post("/v1/payments/:paymentId/refund", refundPayment);
router.delete("/v1/users/:userId", revokeUserAccess);

module.exports = router;
