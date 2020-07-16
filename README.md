# Query CRLite Status

This tool reads public data from the CRLite service to provide some useful status pertaining to recent runs.

It maintains a local database in your `~/.crlitedb/audits` folder, which is the same general place as the [`moz_crlite_query` tool defaults](https://github.com/mozilla/moz_crlite_query).

Install from PyPi:
```sh
pip install crlite_status
```

Calling with only a number will show basic details of that many recent runs:

```
→ crlite_status 6
                                                          Data sizes
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Run ID     ┃ Run Time          ┃ Filter   ┃ Filter Layers ┃ Stash      ┃ Known Revoked ┃ Known Not        ┃ Period Covered ┃
┃            ┃                   ┃          ┃               ┃            ┃               ┃ Revoked          ┃                ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 20200715-0 │ 2020-07-15 23:30Z │ 4.716 MB │ 27            │ 241.846 kB │ 3,627,091     │ 85,411,848       │ 1 day, 5:29:37 │
│ 20200714-3 │ 2020-07-14 18:00Z │ 4.713 MB │ 27            │ 42.293 kB  │ 3,624,884     │ 85,318,616       │ 5:59:55        │
│ 20200714-2 │ 2020-07-14 12:00Z │ 4.715 MB │ 27            │ 52.959 kB  │ 3,625,239     │ 85,279,722       │ 6:00:15        │
│ 20200714-1 │ 2020-07-14 06:00Z │ 4.715 MB │ 28            │ 20.627 kB  │ 3,625,180     │ 85,340,063       │ 5:59:46        │
│ 20200714-0 │ 2020-07-14 00:00Z │ 4.716 MB │ 27            │ 86.515 kB  │ 3,625,935     │ 85,282,318       │ 6:00:15        │
│ 20200713-3 │ 2020-07-13 18:00Z │ 4.712 MB │ 27            │ 46.512 kB  │ 3,623,297     │ 85,239,760       │                │
└────────────┴───────────────────┴──────────┴───────────────┴────────────┴───────────────┴──────────────────┴────────────────┘

```

You can also dig into CRL audit data with the `--crl` flag:

```
→ crlite_status 2 --crl
                                                          Data sizes
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Run ID     ┃ Run Time          ┃ Filter   ┃ Filter Layers ┃ Stash      ┃ Known Revoked ┃ Known Not        ┃ Period Covered ┃
┃            ┃                   ┃          ┃               ┃            ┃               ┃ Revoked          ┃                ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 20200715-0 │ 2020-07-15 23:30Z │ 4.716 MB │ 27            │ 241.846 kB │ 3,627,091     │ 85,411,848       │ 1 day, 5:29:37 │
│ 20200714-3 │ 2020-07-14 18:00Z │ 4.713 MB │ 27            │ 42.293 kB  │ 3,624,884     │ 85,318,616       │ 5:59:55        │
└────────────┴───────────────────┴──────────┴───────────────┴────────────┴───────────────┴──────────────────┴────────────────┘
                                   20200715-0 audit entries
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Issuer                                                       ┃ Kind                ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ CN=Dodo Sign TLS ICA RSA R1,O=Dodo Sign                      │ Older Than Previous │ 1     │
│ Ltd,L=Ebene,ST=Plaines Wilhems,C=MU                          │                     │       │
│ CN=Domain The Net Technologies Ltd CA for EV SSL R2,O=Domain │ Older Than Previous │ 1     │
│ The Net Technologies Ltd,C=IL                                │                     │       │
│ CN=Go Daddy Secure Certificate Authority -                   │ Older Than Previous │ 66    │
│ G2,OU=http://certs.godaddy.com/repository/,O=GoDaddy.com\,   │                     │       │
│ Inc.,L=Scottsdale,ST=Arizona,C=US                            │                     │       │
│ CN=TeleSec Business CA 1,OU=T-Systems Trust                  │ Failed Download     │ 1     │
│ Center,O=T-Systems International GmbH,C=DE                   │                     │       │
│ CN=Starfield Secure Certificate Authority -                  │ Older Than Previous │ 16    │
│ G2,OU=http://certs.starfieldtech.com/repository/,O=Starfield │                     │       │
│ Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US             │                     │       │
│ CN=Domain The Net Technologies Ltd CA for SSL R2,O=Domain    │ Older Than Previous │ 1     │
│ The Net Technologies Ltd,C=IL                                │                     │       │
│ CN=Amazon,OU=Server CA 3B,O=Amazon,C=US                      │ Older Than Previous │ 1     │
│ CN=Starfield Root Certificate Authority -                    │ Very Old, Blocked   │ 1     │
│ G2,OU=https://certs.starfieldtech.com/repository/,O=Starfie… │                     │       │
│ Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US             │                     │       │
│ OU=醫事憑證管理中心,O=行政院,C=TW                               │ Failed Download     │ 1     │
│ CN=SSL.com EV SSL Intermediate CA ECC R2,O=SSL               │ Older Than Previous │ 1     │
│ Corp,L=Houston,ST=Texas,C=US                                 │                     │       │
└──────────────────────────────────────────────────────────────┴─────────────────────┴───────┘
                                   20200714-3 audit entries
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Issuer                                                           ┃ Kind            ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ CN=Starfield Secure Certificate Authority -                      │ Failed Verify   │ 1     │
│ G2,OU=http://certs.starfieldtech.com/repository/,O=Starfield     │                 │       │
│ Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US                 │                 │       │
│ OU=醫事憑證管理中心,O=行政院,C=TW                                   │ Failed Download │ 1     │
│ CN=Go Daddy Secure Certificate Authority -                       │ Failed Verify   │ 80    │
│ G2,OU=http://certs.godaddy.com/repository/,O=GoDaddy.com\,       │                 │       │
│ Inc.,L=Scottsdale,ST=Arizona,C=US                                │                 │       │
│ CN=TeleSec Business CA 1,OU=T-Systems Trust Center,O=T-Systems   │ Failed Download │ 1     │
│ International GmbH,C=DE                                          │                 │       │
│ CN=SHECA RSA Organization Validation Server CA                   │ Failed Download │ 5     │
│ G3,O=UniTrust,C=CN                                               │                 │       │
│ CN=Starfield Root Certificate Authority -                        │ Old             │ 1     │
│ G2,OU=https://certs.starfieldtech.com/repository/,O=Starfield    │                 │       │
│ Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US                 │                 │       │
└──────────────────────────────────────────────────────────────────┴─────────────────┴───────┘

```

When using the `--crl` option, more fine-grained details can be obtained from the JSON files
in `~/.crlite_db/audits/`, or you can use `--crl-details path_to_file.html` and get a rich-text
version.
