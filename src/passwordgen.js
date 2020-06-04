'use strict'

var strongPaswordGenerator = require("strong-password-generator");
var defaultPasswordConfig = {
  base: 'WORD',
  length: {
    min: 12,
    max: 16
  },
  capsLetters: {
    min: 3,
    max: 3
  },
  numerals: {
    min: 2,
    max: 2
  },
  spacialCharactors: {
    includes: ['~','!','@','#','$','%','^','&','*','(',')','_','+','-','=','[',']','\\','{','}','|',';',"'",':','"',',','.','/','<','>','?'],
    min: 2,
    max: 4
  },
  spaces: {
    allow: false,
    min: 0,
    max: 0
  }
};

module.exports = {
  generatePassword: () => {
    const password = strongPaswordGenerator.generatePassword(defaultPasswordConfig);
    return password
  }
} 
