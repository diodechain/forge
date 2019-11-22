var forge = require('./forge');
require('./asn1');
require('./jsbn');
require('./oids');
require('./pkcs1');
require('./prime');
require('./random');
require('./util');

if(typeof BigInteger === 'undefined') {
  var BigInteger = forge.jsbn.BigInteger;
}

var _crypto = forge.util.isNodejs ? require('crypto') : null;

// shortcut for asn.1 API
var asn1 = forge.asn1;

// shortcut for util API
var util = forge.util;

/*
 * ECDSA
 * TODO: add group fields information, add oids, sign method
 */
forge.pki = forge.pki || {};
module.exports = forge.pki.rsa = forge.rsa = forge.rsa || {};
var pki = forge.pki;

const ecPrivateKeyValidator = {
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  value: [{
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    capture: 'Version'
  }, {
    type: asn1.Type.SEQUENCE,
    optional: true,
    value: [{
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      capture: 'KeyType'
    }, {
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      capture: 'CurveName'
    }]
  }, {
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    capture: 'PrivateKey'
  }, {
    type: asn1.Type.BITSTRING,
    capture: 'Publickey',
    optional: true
  }]
};

/**
 * Converts a private key from an ASN.1 object.
 *
 * @param obj the ASN.1 representation of a PrivateKeyInfo containing an
 *          RSAPrivateKey or an RSAPrivateKey.
 *
 * @return the private key.
 */
pki.ecPrivateKeyFromAsn1 = function(obj) {
  // get PrivateKeyInfo
  var capture = {};
  var errors = [];
  // if(asn1.validate(obj, asn1.privateKeyValidator, capture, errors)) {
  //   obj = asn1.fromDer(forge.util.createBuffer(capture.privateKey));
  // }

  // get ECPrivateKey
  capture = {};
  errors = [];
  if(!asn1.validate(obj, ecPrivateKeyValidator, capture, errors)) {
    var error = new Error('Cannot read private key. ' +
      'ASN.1 object does not contain an ECPrivateKey.');
    error.errors = errors;
    throw error;
  }
  const version = forge.util.createBuffer(capture.Version).getInt32()
  const keyType = forge.asn1.derToOid(capture.KeyType)
  const curveName = forge.asn1.derToOid(capture.CurveName)
  const privateKey = forge.util.createBuffer(capture.PrivateKey).toHex()
  return {
    version,
    keyType,
    curveName,
    privateKey
  };
};