# Smeagle Python

Trying to write a Smeagle equivalent tool in Python using [angr](https://github.com/angr/angr)!

## Usage

First create a virtual environment and install dependencies.

```bash
$ python -m venv env
$ source env/bin/activate
```

Then you can run Smeagle Python pointing at a binary.

```bash
$ python smeagle.py libtest.so
```
```
{
    "library": "/home/vanessa/Desktop/Code/smeagle-python/libtest.so",
    "locations": [
        {
            "name": "_init",
            "size": 27,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_401020",
            "size": 13,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_40102d",
            "size": 3,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_401030",
            "size": 15,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_40103f",
            "size": 1,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "__cxa_finalize",
            "size": 11
        },
        {
            "name": "__printf_chk",
            "size": 11
        },
        {
            "name": "deregister_tm_clones",
            "size": 41,
            "parameters": []
        },
        {
            "name": "sub_401089",
            "size": 7,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "register_tm_clones",
            "size": 57,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_4010c9",
            "size": 7,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "__do_global_dtors_aux",
            "size": 54,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_401105",
            "size": 3,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_401109",
            "size": 7,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "frame_dummy",
            "size": 9,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_401119",
            "size": 7,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "_Z7bigcallllllln",
            "size": 54,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "_fini",
            "size": 13,
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        }
    ]
}

```
Not perfect yet (I need to parse types recursively) but wow that was easy and I got
really far in an afternoon!


### License

This project is part of Spack. Spack is distributed under the terms of both the MIT license and the Apache License (Version 2.0). Users may choose either license, at their option.

All new contributions must be made under both the MIT and Apache-2.0 licenses.

See LICENSE-MIT, LICENSE-APACHE, COPYRIGHT, and NOTICE for details.

SPDX-License-Identifier: (Apache-2.0 OR MIT)

LLNL-CODE-811652
