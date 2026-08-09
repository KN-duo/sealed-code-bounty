/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 *
 * Note that this is only a type helper and is not the actual IDL. The original
 * IDL can be found at `target/idl/sealed_code_bounty.json`.
 */
export type SealedCodeBounty = {
  "address": "FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V",
  "metadata": {
    "name": "sealedCodeBounty",
    "version": "0.1.0",
    "spec": "0.1.0",
    "description": "Created with Anchor"
  },
  "instructions": [
    {
      "name": "cancelExpiredBounty",
      "discriminator": [
        71,
        236,
        54,
        65,
        234,
        38,
        82,
        169
      ],
      "accounts": [
        {
          "name": "buyer",
          "writable": true,
          "signer": true
        },
        {
          "name": "bounty",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  111,
                  117,
                  110,
                  116,
                  121
                ]
              },
              {
                "kind": "account",
                "path": "buyer"
              },
              {
                "kind": "arg",
                "path": "bountyId"
              }
            ]
          }
        }
      ],
      "args": [
        {
          "name": "bountyId",
          "type": "u64"
        }
      ]
    },
    {
      "name": "createBounty",
      "discriminator": [
        122,
        90,
        14,
        143,
        8,
        125,
        200,
        2
      ],
      "accounts": [
        {
          "name": "buyer",
          "writable": true,
          "signer": true
        },
        {
          "name": "bounty",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  111,
                  117,
                  110,
                  116,
                  121
                ]
              },
              {
                "kind": "account",
                "path": "buyer"
              },
              {
                "kind": "arg",
                "path": "bountyId"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "bountyId",
          "type": "u64"
        },
        {
          "name": "testSuiteHash",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        },
        {
          "name": "prizeAmount",
          "type": "u64"
        },
        {
          "name": "deadline",
          "type": "i64"
        }
      ]
    },
    {
      "name": "resolveSubmission",
      "discriminator": [
        97,
        58,
        160,
        92,
        75,
        248,
        14,
        127
      ],
      "accounts": [
        {
          "name": "buyer",
          "signer": true
        },
        {
          "name": "bounty",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  111,
                  117,
                  110,
                  116,
                  121
                ]
              },
              {
                "kind": "account",
                "path": "buyer"
              },
              {
                "kind": "arg",
                "path": "bountyId"
              }
            ]
          }
        },
        {
          "name": "solver",
          "writable": true
        }
      ],
      "args": [
        {
          "name": "bountyId",
          "type": "u64"
        },
        {
          "name": "passed",
          "type": "bool"
        }
      ]
    },
    {
      "name": "submitSolution",
      "discriminator": [
        203,
        233,
        157,
        191,
        70,
        37,
        205,
        0
      ],
      "accounts": [
        {
          "name": "solver",
          "writable": true,
          "signer": true
        },
        {
          "name": "bounty",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  111,
                  117,
                  110,
                  116,
                  121
                ]
              },
              {
                "kind": "account",
                "path": "bounty.buyer",
                "account": "bounty"
              },
              {
                "kind": "arg",
                "path": "bountyId"
              }
            ]
          }
        },
        {
          "name": "buyer",
          "writable": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "bountyId",
          "type": "u64"
        },
        {
          "name": "solution",
          "type": "string"
        }
      ]
    }
  ],
  "accounts": [
    {
      "name": "bounty",
      "discriminator": [
        237,
        16,
        105,
        198,
        19,
        69,
        242,
        234
      ]
    }
  ],
  "events": [
    {
      "name": "bountyCancelled",
      "discriminator": [
        234,
        186,
        248,
        214,
        198,
        69,
        152,
        23
      ]
    },
    {
      "name": "bountyCreated",
      "discriminator": [
        68,
        252,
        247,
        196,
        154,
        247,
        130,
        49
      ]
    },
    {
      "name": "bountyResolved",
      "discriminator": [
        250,
        202,
        221,
        27,
        55,
        88,
        103,
        137
      ]
    },
    {
      "name": "solutionSubmitted",
      "discriminator": [
        206,
        122,
        71,
        176,
        145,
        150,
        230,
        5
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "invalidPrizeAmount",
      "msg": "Prize amount must be greater than zero"
    },
    {
      "code": 6001,
      "name": "invalidDeadline",
      "msg": "Deadline must be in the future"
    },
    {
      "code": 6002,
      "name": "solutionTooLong",
      "msg": "Solution exceeds maximum allowed length"
    },
    {
      "code": 6003,
      "name": "alreadySubmitted",
      "msg": "Bounty already has a pending submission"
    },
    {
      "code": 6004,
      "name": "alreadyResolved",
      "msg": "Bounty has already been resolved"
    },
    {
      "code": 6005,
      "name": "noSubmission",
      "msg": "No submission pending for this bounty"
    },
    {
      "code": 6006,
      "name": "solverMismatch",
      "msg": "Solver account does not match the recorded submitter"
    },
    {
      "code": 6007,
      "name": "notExpiredYet",
      "msg": "Bounty deadline has not passed yet"
    }
  ],
  "types": [
    {
      "name": "bounty",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "buyer",
            "type": "pubkey"
          },
          {
            "name": "bountyId",
            "type": "u64"
          },
          {
            "name": "testSuiteHash",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "prizeAmount",
            "type": "u64"
          },
          {
            "name": "deadline",
            "type": "i64"
          },
          {
            "name": "submitted",
            "type": "bool"
          },
          {
            "name": "resolved",
            "type": "bool"
          },
          {
            "name": "solver",
            "type": {
              "option": "pubkey"
            }
          },
          {
            "name": "solution",
            "type": "string"
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    },
    {
      "name": "bountyCancelled",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "bounty",
            "type": "pubkey"
          },
          {
            "name": "buyer",
            "type": "pubkey"
          },
          {
            "name": "bountyId",
            "type": "u64"
          },
          {
            "name": "refundedAmount",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "bountyCreated",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "bounty",
            "type": "pubkey"
          },
          {
            "name": "buyer",
            "type": "pubkey"
          },
          {
            "name": "bountyId",
            "type": "u64"
          },
          {
            "name": "prizeAmount",
            "type": "u64"
          },
          {
            "name": "deadline",
            "type": "i64"
          }
        ]
      }
    },
    {
      "name": "bountyResolved",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "bounty",
            "type": "pubkey"
          },
          {
            "name": "solver",
            "type": "pubkey"
          },
          {
            "name": "bountyId",
            "type": "u64"
          },
          {
            "name": "passed",
            "type": "bool"
          },
          {
            "name": "prizeAmount",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "solutionSubmitted",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "bounty",
            "type": "pubkey"
          },
          {
            "name": "solver",
            "type": "pubkey"
          },
          {
            "name": "bountyId",
            "type": "u64"
          }
        ]
      }
    }
  ],
  "constants": [
    {
      "name": "bountySeed",
      "type": "bytes",
      "value": "[98, 111, 117, 110, 116, 121]"
    },
    {
      "name": "maxSolutionLen",
      "type": "u64",
      "value": "2000"
    },
    {
      "name": "submissionFeeLamports",
      "type": "u64",
      "value": "5000000"
    }
  ]
};
