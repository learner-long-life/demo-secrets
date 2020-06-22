'use strict'

const { Map } = require('immutable')
const strongPaswordGenerator = require("strong-password-generator");

const gens = {}

gens.defaultPasswordConfig = {
  base: 'WORD',
  length: {
    min: 8,
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

gens.bankOfAmericaConfig = Map(gens.defaultPasswordConfig)
  .set('spacialCharactors', {
    includes: ['@', '#', '*', '(', ')', '+', '=', '{', '}', '/', '?', '~', ';', ',', '.', '-', '_'],
    min: 2,
    max: 4
  }).toJS()

gens.generatePassword = (config=gens.defaultPasswordConfig) => {
  const password = strongPaswordGenerator.generatePassword(config);
  return password
}

module.exports = gens
