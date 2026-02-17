const ForeclosureData = require('../models/foreclosureData.model');
const factory = require('./handlerFactory');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

exports.createNewForeclosureData = catchAsync(async (req, res, next) => {
  const newForeclosureData = await ForeclosureData.create({
    applicantName: req.body.applicantName,
    branch: req.body.branch,
    siteLocation: req.body.siteLocation,
    collateralType: req.body.collateralType,
    numberOfCollaterals: req.body.numberOfCollaterals,
    dateOfRequest: req.body.dateOfRequest,
    users: [req.user._id],
  });
  //   const safeUser = newForeclosureData.toObject();

  res.status(201).json({
    status: 'success',

    data: {
      data: newForeclosureData,
    },
  });
});

exports.updateForeclosureData = catchAsync(async (req, res, next) => {
  const updated = await ForeclosureData.findByIdAndUpdate(
    req.params.id,
    {
      ...req.body,
      $addToSet: { users: req.user._id }, // add user if not already present
    },
    { new: true, runValidators: true },
  );
  if (!updated) {
    return next(new AppError('No foreclosure record found with that ID', 404));
  }
  res.status(200).json({ status: 'success', data: { data: updated } });
});
// exports.createNewForeclosureData = factory.createOne(ForeclsdureData);

exports.getAllForeclosureData = factory.getAll(ForeclosureData);

// exports.getOneForeclosureData = factory.getOne(ForeclosureData);
// exports.updateForeclosureData = factory.updateOne(ForeclosureData);
exports.deleteForeclosureData = factory.deleteOne(ForeclosureData);
exports.getOneForeclosureData = catchAsync(async (req, res, next) => {
  const foreclosure = await ForeclosureData.findById(req.params.id).populate(
    'users',
  );

  if (!foreclosure) {
    return next(new AppError('No foreclosure data found wit that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      foreclosure,
    },
  });
});
