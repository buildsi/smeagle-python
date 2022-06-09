# Smeagle Python

Trying to write a Smeagle equivalent tool in Python using [angr](https://github.com/angr/angr)!

## Usage

First create a virtual environment and install dependencies.

```bash
$ python -m venv env
$ source env/bin/activate
```
We need to install pyelftools from it's repo

```bash
pip install git+https://github.com/eliben/pyelftools
```

We need Vanessa's branch of cle and angr:

```bash
pip install angr
pip install --updgrade pip
pip install git+https://github.com/vsoch/cle.git@add/x86-parser-june
pip install packaging
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
            "variables": []
        },
        {
            "function": {
                "name": "_ZN11MathLibrary10Arithmetic3AddEdd",
                "parameters": [
                    {
                        "size": 8,
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm0"
                    },
                    {
                        "size": 8,
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm1"
                    }
                ],
                "return": {
                    "type": "double",
                    "size": 8,
                    "class": "Float",
                    "location": "%xmm0"
                },
                "direction": "export"
            }
        },
        {
            "function": {
                "name": "_ZN11MathLibrary10Arithmetic8SubtractEdd",
                "parameters": [
                    {
                        "size": 8,
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm0"
                    },
                    {
                        "size": 8,
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm1"
                    }
                ],
                "return": {
                    "type": "double",
                    "size": 8,
                    "class": "Float",
                    "location": "%xmm0"
                },
                "direction": "export"
            }
        },
        {
            "function": {
                "name": "_ZN11MathLibrary10Arithmetic8MultiplyEdd",
                "parameters": [
                    {
                        "size": 8,
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm0"
                    },
                    {
                        "size": 8,
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm1"
                    }
                ],
                "return": {
                    "type": "double",
                    "size": 8,
                    "class": "Float",
                    "location": "%xmm0"
                },
                "direction": "export"
            }
        },
        {
            "function": {
                "name": "_ZN11MathLibrary10Arithmetic6DivideEdd",
                "parameters": [
                    {
                        "size": 8,
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm0"
                    },
                    {
                        "size": 8,
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm1"
                    }
                ],
                "return": {
                    "type": "double",
                    "size": 8,
                    "class": "Float",
                    "location": "%xmm0"
                },
                "direction": "export"
            }
        }
    ]
}
```

We have basic callsite parsing from angr:

```bash
$ python smeagle.py ../cle/examples/callsite/lib.so 
{
    "library": "/home/vanessa/Desktop/Code/cle/examples/callsite/lib.so",
    "locations": [
        {
            "variables": []
        },
        {
            "function": {
                "name": "_Z5startd",
                "parameters": [
                    {
                        "size": 8,
                        "name": "d",
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm0"
                    }
                ],
                "return": {
                    "type": "int",
                    "size": 4,
                    "class": "Integer",
                    "location": "%rax"
                },
                "direction": "export"
            }
        },
        {
            "function": {
                "name": "_Z3bard",
                "parameters": [
                    {
                        "size": 8,
                        "name": "d",
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm0"
                    }
                ],
                "return": {
                    "type": "double",
                    "size": 8,
                    "class": "Float",
                    "location": "%xmm0"
                },
                "direction": "export"
            }
        },
        {
            "function": {
                "name": "_Z3fooi",
                "parameters": [
                    {
                        "size": 4,
                        "name": "x",
                        "type": "int",
                        "class": "Integer",
                        "location": "%rdi"
                    }
                ],
                "return": {
                    "type": "int",
                    "size": 4,
                    "class": "Integer",
                    "location": "%rax"
                },
                "direction": "export"
            }
        },
        {
            "callsite": {
                "name": "_Z3fooi",
                "parameters": [
                    {
                        "size": 4,
                        "name": "x",
                        "type": "int",
                        "class": "Integer",
                        "location": "%rdi"
                    }
                ],
                "return": {
                    "type": "int",
                    "size": 4,
                    "class": "Integer",
                    "location": "%rax"
                },
                "direction": "export"
            }
        },
        {
            "callsite": {
                "name": "_Z3bard",
                "parameters": [
                    {
                        "size": 8,
                        "name": "d",
                        "type": "double",
                        "class": "Float",
                        "location": "%xmm0"
                    }
                ],
                "return": {
                    "type": "double",
                    "size": 8,
                    "class": "Float",
                    "location": "%xmm0"
                },
                "direction": "export"
            }
        }
    ]
}
```

### License

This project is part of Spack. Spack is distributed under the terms of both the MIT license and the Apache License (Version 2.0). Users may choose either license, at their option.

All new contributions must be made under both the MIT and Apache-2.0 licenses.

See LICENSE-MIT, LICENSE-APACHE, COPYRIGHT, and NOTICE for details.

SPDX-License-Identifier: (Apache-2.0 OR MIT)

LLNL-CODE-811652
