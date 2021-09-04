const AWS = require('aws-sdk');
const qs = require('qs');
const crypto = require('crypto-js');
const fetch = require('isomorphic-unfetch')
require('dotenv').config()

// 1.access_token取得
const getAccessToken = async () => {
  const response = await fetch('https://api.amazon.com/auth/o2/token', {
    method: 'post',
    headers: {
      "Content-Type": "application/json",
      "Content-Length": 524
    },
    body: JSON.stringify({
      grant_type: 'refresh_token',
      client_id: process.env.SELLER_CLIENT_ID,
      client_secret: process.env.SELLER_CLIENT_SECRET,
      refresh_token: process.env.SELLER_REFRESH_TOKEN
    })
  }).then(res => res.json())
  return response
}


// 2.AWS STS security token service
const createTemporaryAWSCredentials = async () => {
  const SESConfig = {
    region: 'us-west-2',
    credentials: new AWS.Credentials(process.env.AWS_ACCESS_KEY, process.env.AWS_SECRET_KEY)
  }
  const STS = new AWS.STS();
  STS.config.update(SESConfig)
  const response = await STS.assumeRole({
    RoleArn: process.env.ROLE_ARN,
    RoleSessionName: process.env.ROLE_ARN_NAME,
  }).promise();
  return response.Credentials
};


// 3.AWS Signature (リクエスト作成)
const getAuthorizationHeader = (access_token, role_credentials, req_params) => {
  req_params.query = sortQuery(req_params.query);
  let iso_date = createUTCISODate();

  let encoded_query_string = constructEncodedQueryString(req_params.query);
  let canonical_request = constructCanonicalRequestForAPI(access_token, req_params, encoded_query_string, iso_date);
  let string_to_sign = constructStringToSign('us-west-2', 'execute-api', canonical_request, iso_date);
  let signature = constructSignature('us-west-2', 'execute-api', string_to_sign, role_credentials.secret, iso_date);

  return {
    method:req_params.method,
    url: constructURL(req_params, encoded_query_string),
    body:req_params.body ? JSON.stringify(req_params.body) : null,
    headers: {
      'Authorization':'AWS4-HMAC-SHA256 Credential=' + role_credentials.id + '/' + iso_date.short + '/' + 'us-west-2' + '/execute-api/aws4_request, SignedHeaders=host;x-amz-access-token;x-amz-date, Signature=' + signature,
      'Content-Type': 'application/json; charset=utf-8',
      'host': "sellingpartnerapi-fe.amazon.com",
      'x-amz-access-token':access_token,
      'x-amz-security-token':role_credentials.security_token,
      'x-amz-date': iso_date.full
    }
  }
}

const constructURL = (req_params, encoded_query_string) => {
  let url = 'https://sellingpartnerapi-fe.amazon.com' + req_params.api_path;
  if (encoded_query_string !== ''){
    url += '?' + encoded_query_string;
  }
  return url;
}

const sortQuery = (query) => {
  if (query && Object.keys(query).length){
    return Object.keys(query).sort().reduce((r, k) => (r[k] = query[k], r), {});
  }
  return;
}

const createUTCISODate = () => {
  let iso_date = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
  return {
    short:iso_date.substr(0,8),
    full:iso_date
  };
}

const constructEncodedQueryString = (query) => {
  if (query){
    query = qs.stringify(query, {arrayFormat:'comma'});
    let encoded_query_obj = {};
    let query_params = query.split('&');
    query_params.map((query_param) => {
      let param_key_value = query_param.split('=');
      encoded_query_obj[param_key_value[0]] = param_key_value[1];
    });
    encoded_query_obj = sortQuery(encoded_query_obj);
    let encoded_query_arr = [];
    for (let key in encoded_query_obj){
      encoded_query_arr.push(key + '=' + encoded_query_obj[key]);
    }
    if (encoded_query_arr.length){
      return encoded_query_arr.join('&');
    }
  }
  return '';
}

const constructCanonicalRequestForAPI = (access_token, params, encoded_query_string, iso_date) => {
  let canonical = [];
  canonical.push(params.method);
  canonical.push(params.api_path);
  canonical.push(encoded_query_string);
  canonical.push('host:sellingpartnerapi-fe.amazon.com');
  canonical.push('x-amz-access-token:' + access_token);
  canonical.push('x-amz-date:' + iso_date.full);
  canonical.push('');
  canonical.push('host;x-amz-access-token;x-amz-date');
  canonical.push(crypto.SHA256(params.body ? JSON.stringify(params.body) : ''));
  return canonical.join('\n');
}

const constructStringToSign = (region, action_type, canonical_request, iso_date) => {
  let string_to_sign = [];
  string_to_sign.push('AWS4-HMAC-SHA256')
  string_to_sign.push(iso_date.full);
  string_to_sign.push(iso_date.short + '/' + region + '/' + action_type + '/aws4_request');
  string_to_sign.push(crypto.SHA256(canonical_request));
  return string_to_sign.join('\n');
}

const constructSignature = (region, action_type, string_to_sign, secret, iso_date) => {
  let signature = crypto.HmacSHA256(iso_date.short, 'AWS4' + secret);
  signature = crypto.HmacSHA256(region, signature);
  signature = crypto.HmacSHA256(action_type, signature);
  signature = crypto.HmacSHA256('aws4_request', signature);
  return crypto.HmacSHA256(string_to_sign, signature).toString(crypto.enc.Hex);
}

const req_params = {
  api_path: "/reports/2020-09-04/reports",
  method: "GET",
  query: {reportTypes: ["GET_V2_SETTLEMENT_REPORT_DATA_FLAT_FILE"]},
}

const main = async () => {
  // 1.access_token取得
  const auth_token = await getAccessToken()
  // 2.STS security token service
  const credentials = await createTemporaryAWSCredentials()
  const role_credentials = {
    id: credentials.AccessKeyId,
    secret: credentials.SecretAccessKey,
    security_token: credentials.SessionToken
  }
  // 3.AWS signature(著名)
  let auth = await getAuthorizationHeader(auth_token.access_token, role_credentials, req_params);
  // 4.APIを叩く
  const response = await fetch(auth.url, {
    method: auth.method,
    headers: auth.headers
  }).then(res => res.json()).catch(err => console.log(err))
  console.log(response)
}

main()
