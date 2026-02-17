const express = require('express');
const foreclosureDataController = require('../../controllers/foreclosureData.controller');
const authController = require('../../controllers/auth.controller');
const router = express.Router();

router
  .route('/')
  .get(authController.protect, foreclosureDataController.getAllForeclosureData)
  .post(
    authController.protect,
    foreclosureDataController.createNewForeclosureData,
  );
router
  .route('/:id')
  .get(authController.protect, foreclosureDataController.getOneForeclosureData)
  .patch(
    authController.protect,
    foreclosureDataController.updateForeclosureData,
  )
  .delete(
    authController.protect,
    authController.restrictTo('admin', 'senior'),
    foreclosureDataController.deleteForeclosureData,
  );
module.exports = router;
