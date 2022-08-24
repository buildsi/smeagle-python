# Smeagle Python

Trying to write a Smeagle equivalent tool in Python using [angr](https://github.com/angr/angr)!

**Note** This repository is deprecated, and you should use [https://github.com/buildsi/smeagle-py](https://github.com/buildsi/smeagle-py) instead. However note that they use different approaches to achieve "the same" thing, so you can inspect and decide for yourself.

## Usage

First create a virtual environment and install dependencies.

```bash
$ python -m venv env
$ source env/bin/activate
```

Compile the example

```bash
cd example
make
```

Then you can run Smeagle Python pointing at a binary.

```bash
$ python smeagle.py example/libmath-v1.so
```
```
{
    "library": "/home/vanessa/Desktop/Code/smeagle-python/example/libmath-v1.so",
    "locations": [
        {
            "name": "_init",
            "size": 27,
            "direction": "unknown",
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
            "direction": "unknown",
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
            "direction": "unknown",
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
            "size": 11,
            "direction": "unknown"
        },
        {
            "name": "deregister_tm_clones",
            "size": 41,
            "direction": "unknown",
            "parameters": []
        },
        {
            "name": "sub_401069",
            "size": 7,
            "direction": "unknown",
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
            "direction": "unknown",
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_4010a9",
            "size": 7,
            "direction": "unknown",
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
            "direction": "unknown",
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_4010e5",
            "size": 3,
            "direction": "unknown",
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_4010e9",
            "size": 7,
            "direction": "unknown",
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
            "direction": "unknown",
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "sub_4010f9",
            "size": 1,
            "direction": "unknown",
            "parameters": [
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "_ZN11MathLibrary10Arithmetic3AddEdd",
            "size": 30,
            "direction": "export",
            "parameters": [
                {
                    "type": "void *",
                    "size": 64,
                    "location": "rdi"
                },
                {
                    "type": "double",
                    "size": 64,
                    "location": "xmm0"
                },
                {
                    "type": "double",
                    "size": 64,
                    "location": "xmm1"
                },
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "_ZN11MathLibrary10Arithmetic8SubtractEdd",
            "size": 30,
            "direction": "export",
            "parameters": [
                {
                    "type": "void *",
                    "size": 64,
                    "location": "rdi"
                },
                {
                    "type": "double",
                    "size": 64,
                    "location": "xmm0"
                },
                {
                    "type": "double",
                    "size": 64,
                    "location": "xmm1"
                },
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "_ZN11MathLibrary10Arithmetic8MultiplyEdd",
            "size": 30,
            "direction": "export",
            "parameters": [
                {
                    "type": "void *",
                    "size": 64,
                    "location": "rdi"
                },
                {
                    "type": "double",
                    "size": 64,
                    "location": "xmm0"
                },
                {
                    "type": "double",
                    "size": 64,
                    "location": "xmm1"
                },
                {
                    "type": "int",
                    "size": 32,
                    "location": "rax"
                }
            ]
        },
        {
            "name": "_ZN11MathLibrary10Arithmetic6DivideEdd",
            "size": 30,
            "direction": "export",
            "parameters": [
                {
                    "type": "void *",
                    "size": 64,
                    "location": "rdi"
                },
                {
                    "type": "double",
                    "size": 64,
                    "location": "xmm0"
                },
                {
                    "type": "double",
                    "size": 64,
                    "location": "xmm1"
                },
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
            "direction": "unknown",
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
