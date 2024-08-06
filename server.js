require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const AWS = require('aws-sdk');
const multer = require('multer');
const { createObjectCsvWriter } = require('csv-writer');
const { createObjectCsvStringifier } = require('csv-writer');
const fs = require('fs');
const axios = require('axios');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const crypto = require('crypto');
const csv = require('csv-parser');
const twilio = require('twilio');
const https = require('https');


const csvParse = require('csv-parse')


const app = express();
const port = 5000;

// const BUSINESS_PAN_SIGNZY_API_URL = 'https://api-preproduction.signzy.app/api/v3/businessPan/fetch';
// const SIGNZY_API_URL = 'https://api-preproduction.signzy.app/api/v3/pan/fetch';


// Twilio configuration
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioClient = twilio(accountSid, authToken);

// const url = 'https://graph.facebook.com/v13.0/324620457401875/messages';
// const token = 'EAANz4bu5mggBO6aI8ZAX9AkjPWFRnzHC4NIet4iQx4Hkptj6EROrdPvEHzzzbuJdG4ksWLHhKeKN8wmBrxx8MnbhzfaNLe5qGIWvqZCFuWD9q2Hvpz67gmWCaInkdvGgqsGZBYDloa9caajnmv45dSQbJLOU71KpmdYUK1wpKZCo7a7chNPsxMiW52w5PhqWecHpbOOnmSMbTLqUzzoZD';


const s3 = new AWS.S3();
const upload = multer();
var signupEmail="";

app.use(bodyParser.json());
app.use(cors({
  origin:'http://13.126.52.212:8080'
}));
const secret = crypto.randomBytes(64).toString('hex');

// Express session middleware
app.use(session({
  secret: secret,
  resave: false,
  saveUninitialized: false
}));


// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});


const csvWriter = createObjectCsvWriter({
  path: 'signup.csv',
  header: [
    { id: 'name', title: 'Name' },
    { id: 'email', title: 'Email' },
    { id: 'password', title: 'Password' },
    { id: 'googleId', title: 'Google ID' }
  ]
});

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://13.126.52.212:5000/auth/google/callback',
  scope: ['profile', 'email'] 
},
function(accessToken, refreshToken, profile, done) {
  const userData = {
    name: profile.displayName,
    email: profile.emails[0].value,
    googleId: profile.id
  };

  // Write data to CSV file
  csvWriter.writeRecords([userData]);

  return done(null, profile);
}
));




// Endpoint to handle Google login
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Endpoint to handle Google callback
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  function(req, res) {
    console.log("success");
    res.status(200).json({ message: "success" });
  }
);

// Endpoint to handle signup form submission
app.post('/', upload.none(), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    signupEmail=email;
    const s3Params = {
      Bucket: 'lambda-bucket-trigger-new',
      Key: 'signup.csv'
    };

    // Download the existing signup.csv from S3
    let existingFile = null;
    try {
      existingFile = await s3.getObject(s3Params).promise();
    } catch (err) {
      if (err.code !== 'NoSuchKey') {
        throw err;
      }
    }

    // Process the existing file or create a new one
    let csvData = '';
    const header = ['Name', 'Email', 'Password'];
    let records = [];

    if (existingFile) {
      // Parse the existing CSV data
      csvData = existingFile.Body.toString();
      records = csvData.split('\n').slice(1).map(line => {
        const [name, email, password] = line.split(',');
        return { name, email, password };
      });
    }

    // Check if the email already exists
    const emailExists = records.some(record => record.email === email);
    if (emailExists) {
      console.log("Email already exists");
      return res.status(400).json({ message: 'Email already exists, please login' });
    }

    // Append new data
    records.push({ name, email, password });

    // Create CSV string from records
    const csvString = [
      header.join(','),
      ...records.map(record => `${record.name},${record.email},${record.password}`)
    ].join('\n');

    // Upload the updated CSV file to S3
    const uploadParams = {
      Bucket: 'lambda-bucket-trigger-new',
      Key: 'signup.csv',
      Body: csvString
    };

    await s3.putObject(uploadParams).promise();

    res.status(200).json({ message: 'Form data saved successfully', redirectUrl: '/BusinessOwner' });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint to handle login form submission
app.post('/login', upload.none(), async (req, res) => {
  try {
    const { email, password } = req.body;
    const s3Params = {
      Bucket: 'lambda-bucket-trigger-new',
      Key: 'signup.csv'
    };

    // Download the existing signup.csv from S3
    let existingFile = null;
    try {
      existingFile = await s3.getObject(s3Params).promise();
    } catch (err) {
      if (err.code !== 'NoSuchKey') {
        throw err;
      }
    }

    if (!existingFile) {
      return res.status(400).json({ message: 'No users found. Please sign up first.' });
    }

    // Parse the existing CSV data
    const csvData = existingFile.Body.toString();
    const records = csvData.split('\n').slice(1).map(line => {
      const [name, email, password] = line.split(',');
      return { name, email, password };
    });

    // Check if the email and password match
    const user = records.find(record => record.email === email && record.password === password);

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    res.status(200).json({ message: 'Login successful', redirectUrl: '/merchant', merchantName: user.name });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



app.post('/businessOwner', upload.none(), async (req, res) => {
  try {
    const { fname, lname, email, jobTitle, dob, address1, address2, city, state, zipcode, country, pan } = req.body;

    const response = await axios.post(
      process.env.SIGNZY_API_URL,
      { number: pan,
        returnIndividualTaxComplianceInfo: "true"
       },
      {
        headers: {
          'Authorization': `${process.env.AUTH_TOKEN}`,
          'Content-Type': 'application/json',
        },
      }
    );

    if (response.status === 200) {
      const bucketName = 'lambda-bucket-trigger-new';
      const csvFileName = 'BusinessOwner.csv';

      // Parameters to fetch the existing CSV file from S3
      const params = {
        Bucket: bucketName,
        Key: csvFileName,
      };

      let existingRecords = [];
      let csvHeader = '';

      try {
        const existingFile = await s3.getObject(params).promise();
        const csvData = existingFile.Body.toString();
        existingRecords = csvData.split('\n').slice(1).filter(line => line.trim()).map(line => {
          const [signupEmail, fname, lname, email, jobTitle, dob, address1, address2, city, state, zipcode, country, pan] = line.split(',');
          return { signupEmail, fname, lname, email, jobTitle, dob, address1, address2, city, state, zipcode, country, pan };
        });

        // Use the existing header
        csvHeader = csvData.split('\n')[0] + '\n';
      } catch (err) {
        if (err.code !== 'NoSuchKey') {
          throw err;
        }

        // If file does not exist, create a new header
        csvHeader = 'Signup,FirstName,LastName,Email,JobTitle,DOB,Address1,Address2,City,State,Zipcode,Country,PAN\n';
      }

      // Add the new record
      existingRecords.push({ signupEmail, fname, lname, email, jobTitle, dob, address1, address2, city, state, zipcode, country, pan });

      // Create the CSV stringifier
      const csvStringifier = createObjectCsvStringifier({
        header: [
          { id: 'signupEmail', title: 'Signup' },
          { id: 'fname', title: 'FirstName' },
          { id: 'lname', title: 'LastName' },
          { id: 'email', title: 'Email' },
          { id: 'jobTitle', title: 'JobTitle' },
          { id: 'dob', title: 'DOB' },
          { id: 'address1', title: 'Address1' },
          { id: 'address2', title: 'Address2' },
          { id: 'city', title: 'City' },
          { id: 'state', title: 'State' },
          { id: 'zipcode', title: 'Zipcode' },
          { id: 'country', title: 'Country' },
          { id: 'pan', title: 'PAN' },
        ],
      });

      // Convert records to CSV string
      const csvBody = csvStringifier.stringifyRecords(existingRecords);
      const updatedCsvData = csvHeader + csvBody;

      // Upload the updated CSV data to S3
      const uploadParams = {
        Bucket: bucketName,
        Key: csvFileName,
        Body: updatedCsvData,
        ContentType: 'text/csv'
      };

      await s3.upload(uploadParams).promise();

      console.log("PAN Verified");
      res.status(200).json({ status: 'success', message: 'PAN data verified successfully and Business Owner data saved successfully', redirectUrl: '/business' });
    } else {
      console.log("PAN verification failed");
      res.json({ status: 'error', message: 'PAN verification failed.' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'PAN verification failed' });
  }
});

app.post('/business', async (req, res) => {
  

  const bucketName = 'lambda-bucket-trigger-new';
  const csvFileName = 'Business.csv';
  const { bname, btype, country, bpan, gstin, cin, address1, address2, city, state, zipcode, contact, paymentMode } = req.body;
  const paymentModeString = paymentMode.join(',');

  let existingRecords = [];
  let csvHeader;

  try {
      
      const params = { Bucket: bucketName, Key: csvFileName };
      const existingFile = await s3.getObject(params).promise();
      const csvData = existingFile.Body.toString();
      existingRecords = csvData.split('\n').slice(1).filter(line => line.trim()).map(line => {
          const [signupEmail, bname, btype, country, bpan, gstin, cin, address1, address2, city, state, zipcode, contact, paymentMode] = line.split(',');
          return { signupEmail, bname, btype, country, bpan, gstin, cin, address1, address2, city, state, zipcode, contact, paymentMode };
      });

      // Use the existing header
      csvHeader = csvData.split('\n')[0] + '\n';
  } catch (err) {
      if (err.code !== 'NoSuchKey') {
          return res.status(500).json({ message: 'Error retrieving existing file' });
      }

      // If file does not exist, create a new header
      csvHeader = 'Signup,Business Name,Business Type,Country,Business PAN,GSTIN,CIN,Address Line 1,Address Line 2,City,State,Postal Code,Business Contact,Payment Mode\n';
  }

  // Add the new record
  existingRecords.push({ signupEmail, bname, btype, country, bpan, gstin, cin, address1, address2, city, state, zipcode, contact, paymentMode: paymentModeString });

  // Create the CSV stringifier
  const csvStringifier = createObjectCsvStringifier({
      header: [
          { id: 'signupEmail', title: 'Signup' },
          { id: 'bname', title: 'Business Name' },
          { id: 'btype', title: 'Business Type' },
          { id: 'country', title: 'Country' },
          { id: 'bpan', title: 'Business PAN' },
          { id: 'gstin', title: 'GSTIN' },
          { id: 'cin', title: 'CIN' },
          { id: 'address1', title: 'Address Line 1' },
          { id: 'address2', title: 'Address Line 2' },
          { id: 'city', title: 'City' },
          { id: 'state', title: 'State' },
          { id: 'zipcode', title: 'Postal Code' },
          { id: 'contact', title: 'Business Contact' },
          { id: 'paymentMode', title: 'Payment Mode' },
      ],
  });

  // Convert records to CSV string
  const csvBody = csvStringifier.stringifyRecords(existingRecords);
  const updatedCsvData = csvHeader + csvBody;

  // Upload the updated CSV data to S3
  const uploadParams = {
      Bucket: bucketName,
      Key: csvFileName,
      Body: updatedCsvData,
      ContentType: 'text/csv',
  };

  try {
      await s3.upload(uploadParams).promise();
      res.status(200).json({ message: 'Data successfully saved!', redirectUrl:'/success' });
  } catch (error) {
      console.error('Error uploading file:', error);
      res.status(500).json({ message: 'Error saving data' });
  }
});
app.post('/merchant', async (req, res) => {
  try {
    const { merchantName, date, action } = req.body;
    console.log(action);
    console.log(date);
    const fileName = 'credit_card_details.csv';

    // Read CSV file from S3 bucket
    const s3Params = { Bucket: 'lambda-bucket-trigger-new', Key: fileName };
    const fileData = await s3.getObject(s3Params).promise();
    const csvContent = fileData.Body.toString();

    // Parse CSV data
    const rows = csvContent.split('\n');
    const header = rows[0].split(',');
    const accountNumberIndex = header.indexOf('Account Number');
    const cardOwnerIndex = header.indexOf('Card Owner');
    const paymentAmountIndex = header.indexOf('Payment Amount');
    const dateTimeIndex = header.indexOf('Date and Time');

    // Find index of 'merchantName' column
    const merchantIndex = header.indexOf('Merchant Name');

     // Convert date to dd/mm/yyyy format
     const convertToDDMMYYYY = (inputDate) => {
      const [year, month, day] = inputDate.split('-');
      return `${day}/${parseInt(month)}/${year}`; // Remove leading zero from month
    };

    const formattedDate = convertToDDMMYYYY(date);
    console.log(formattedDate);

    // Filter rows containing the specified merchant name
    let merchantRows = rows.filter((row, index) => {
      if (index === 0) return false; // Skip header row
      const columns = row.split(',');
      return columns[merchantIndex] === merchantName;
    });



    // Check if name parameter is 'last', if so, get the last transaction row
    if (action == "last") {
      merchantRows = [merchantRows[merchantRows.length - 1]]; // Get the last row
      const responseData = merchantRows.map(row => {
        const columns = row.split(',');
        return {
          'Account Number': columns[accountNumberIndex],
          'Card Owner': columns[cardOwnerIndex],
          'Payment Amount': columns[paymentAmountIndex],
          'Date and Time': `${columns[dateTimeIndex].split(' ')[0]} ${columns[dateTimeIndex + 1]}`
        };
      });
       console.log(responseData);
      res.status(200).json(responseData);
    }
    else if(action=='history'){
    // Prepare response
    const responseData = merchantRows.map(row => {
      const columns = row.split(',');
      return header.reduce((acc, key, index) => {
        acc[key] = columns[index];
        return acc;
      }, { 'Time': columns[dateTimeIndex + 1] });
    });
     console.log(responseData);
    res.status(200).json(responseData);
  }
  else if (action === "graph") {
    const dateRows = merchantRows.filter(row => {
      const columns = row.split(',');
      const rowDate = columns[dateTimeIndex].split(' ')[0];
      return rowDate === formattedDate;
    });

    const graphData = dateRows.map(row => {
      const columns = row.split(',');
      return {
        date: columns[dateTimeIndex].split(' ')[0],
        time: columns[dateTimeIndex + 1], // Add time to the response
        amount: parseFloat(columns[paymentAmountIndex])
      };
    });

    console.log(graphData);
    res.status(200).json(graphData);
  }
  
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.post('/creditCard', upload.none(), async (req, res) => {
  try {
    console.log("In /creditCard");
    const { cardNumber, cardOwner, cvv, accountNumber, contactNumber, expiryMonth, expiryYear, addressLine1, addressLine2, city, state, country, postalCode, paymentAmount, merchantName } = req.body;
    const fileName = 'credit_card_details.csv';

    let header = [
      { id: 'cardNumber', title: 'Card Number' },
      { id: 'cardOwner', title: 'Card Owner' },
      { id: 'cvv', title: 'CVV' },
      { id: 'accountNumber', title: 'Account Number' },
      { id: 'contactNumber', title: 'Contact Number' },
      { id: 'expiryMonth', title: 'Expiry Month' },
      { id: 'expiryYear', title: 'Expiry Year' },
      { id: 'addressLine1', title: 'Address Line 1' },
      { id: 'addressLine2', title: 'Address Line 2' },
      { id: 'city', title: 'City' },
      { id: 'state', title: 'State' },
      { id: 'country', title: 'Country' },
      { id: 'postalCode', title: 'Postal Code' },
      { id: 'paymentAmount', title: 'Payment Amount' },
      { id: 'merchantName', title: 'Merchant Name' },
      { id: 'dateAndTime', title: 'Date and Time' }
    ];

    // Check if the file exists in S3
    let existingFile = null;
    try {
      existingFile = await s3.getObject({ Bucket: 'lambda-bucket-trigger-new', Key: fileName }).promise();
    } catch (error) {
      // File does not exist
    }

    // Write data to CSV file
    let csvData = '';
    if (existingFile) {
      // Append new data to existing content
      csvData = existingFile.Body.toString() + '\n';
    } else {
      // Create new file with header
      csvData = header.map(column => column.title).join(',') + '\n';
    }
   const formatDate = (date) => {
      const d = new Date(date);
      const day = String(d.getDate()).padStart(2, '0');
      const month = String(d.getMonth() + 1).padStart(2, '0'); // Months are zero-based
      const year = d.getFullYear();
      return `${day}/${parseInt(month)}/${year}`;
    };

   const formatTime = (date) => {
      const d = new Date(date);
      let hours = d.getHours();
      const minutes = String(d.getMinutes()).padStart(2, '0');
      const seconds = String(d.getSeconds()).padStart(2, '0');
      const ampm = hours >= 12 ? 'PM' : 'AM';
      hours = hours % 12;
      hours = hours ? hours : 12; // the hour '0' should be '12'
      return `${hours}:${minutes}:${seconds} ${ampm}`;
    };

    const date = formatDate(new Date());
    const time = formatTime(new Date());

    csvData += [cardNumber, cardOwner, cvv, accountNumber, contactNumber, expiryMonth, expiryYear, addressLine1, addressLine2, city, state, country, postalCode, paymentAmount, merchantName, date, time].join(',') + '\n';

    // csvData += [cardNumber, cardOwner, cvv, accountNumber, contactNumber, expiryMonth, expiryYear, addressLine1, addressLine2, city, state, country, postalCode, paymentAmount, merchantName, new Date().toLocaleString()].join(',') + '\n';

    await s3.putObject({ Bucket: 'lambda-bucket-trigger-new', Key: fileName, Body: csvData }).promise();

    // Send WhatsApp message through twilio
    twilioClient.messages
      .create({
        from: 'whatsapp:+14155238886',
        to: `whatsapp:+${contactNumber}`,
        body: `Payment confirmation: Your payment of ${paymentAmount} has been successfully processed.`,
      })
      .then((message) => console.log('WhatsApp message sent:', message.sid))
      .catch((error) => console.error('Error sending WhatsApp message:', error));

// Send WhatsApp message through whatsapp business api

// const data = JSON.stringify({
//   messaging_product: 'whatsapp',
//   to: `whatsapp:917668191238`, // Replace with the recipient's WhatsApp number in international format
//   type: 'text',
//   text: {
//     body: `Payment confirmation: Your payment of ${paymentAmount} has been successfully processed.`
//   }
// });

// const options = {
//   hostname: 'graph.facebook.com',
//   path: url,
//   method: 'POST',
//   headers: {
//     'Content-Type': 'application/json',
//     'Authorization': `Bearer ${token}`,
//     'Content-Length': data.length
//   }
// };

// const request = https.request(options, (response) => {
//   let responseData = '';

//   response.on('data', (chunk) => {
//     responseData += chunk;
//   });

//   response.on('end', () => {
//     console.log('WhatsApp message sent:', JSON.parse(responseData));
//   });
// });

// request.on('error', (error) => {
//   console.error('Error sending WhatsApp message:', error);
// });

// request.write(data);
// request.end();



    // Call another Lambda function via API Gateway
    const lambdaApiUrl = process.env.LAMBDA_API_URL; // URL of the API Gateway endpoint for the Lambda function
    const fooValue = '38924952018'; // Value for the foo parameter
    const lambdaResponse = await fetch(`${lambdaApiUrl}?foo=${fooValue}`, {
      method: 'GET', // Change method to 'GET' since we're passing the parameter in the query string
      headers: {
        'x-api-key': process.env.API_KEY // Include the API key here
      }
    });

    const lambdaData = await lambdaResponse.json();
    console.log('Lambda function response:', lambdaData);

    res.status(200).json({ message: 'Form data saved successfully', lambdaResponse: lambdaData, redirectUrl: '/confirm', paymentAmount:paymentAmount, accountNumber:accountNumber, cardOwner:cardOwner });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.post('/confirm', (req, res) => {
  const { action } = req.body;

  if (action === 'confirm') {
    res.status(200).json({ redirectUrl: '/accountManagement' });
  } else if (action === 'cancel') {
    res.status(200).json({ redirectUrl: '/' });
  } else {
    res.status(400).json({ error: 'Invalid action' });
  }
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

