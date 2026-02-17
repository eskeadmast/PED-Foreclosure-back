const mongoose = require('mongoose');

const foreclosureDataSchema = mongoose.Schema({
  applicantName: {
    type: String,
    required: [true, 'Foreclosure data should have an applicant name'],
    trim: true,
  },
  branch: {
    type: String,
    required: [true, 'Foreclosure data should have branch name'],
    trim: true,
  },
  siteLocation: {
    type: String,
    required: [true, 'Foreclosure data should have location of the site'],
    trim: true,
  },
  collateralType: {
    type: String,
    required: [true, 'Foreclosure data should have collateral type'],
    enum: {
      values: ['building', 'vehicle', 'machinery'],
      message: 'Collateral type is either: building, vehicle or machinery',
    },
  },
  numberOfCollaterals: {
    type: Number,
    min: 1,
    required: [true, 'Foreclosure data should have number of collaterals'],
  },
  dateOfRequest: {
    type: Date,
    required: [true, 'Foreclosure data should have date of request'],
  },
  dateOfAppointment: {
    type: Date,
  },
  dateOfReport: {
    type: Date,
  },
  reportStatus: {
    type: String,
    enum: {
      values: ['canceled', 'in-progress', 'reported', 'pending'],
      message: 'Status is either: canceled, in progress, reported or pending',
    },
    default: 'pending',
  },
  engineerName: {
    type: String,
  },
  remarks: {
    type: String,
  },
  startDate: Date,
  endDate: Date,
  users: [
    {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
    },
  ],
});
foreclosureDataSchema.index(
  {
    applicantName: 1,
    branch: 1,
    siteLocation: 1,
    collateralType: 1,
    dateOfRequest: 1,
  },
  {
    unique: true,
    collation: { locale: 'en', strength: 2 },
  },
);

foreclosureDataSchema.pre('save', function () {
  this.dateOfRequest.setHours(0, 0, 0, 0);
});
const ForeclosureData = mongoose.model(
  'ForeclosureData',
  foreclosureDataSchema,
);
module.exports = ForeclosureData;
