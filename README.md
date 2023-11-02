# Project Stellar CSO Compressor
<p >
 <a href=""><img src="https://img.shields.io/discord/643467096906399804.svg" alt="Chat"></a>
 <a href="https://github.com/MakeMHz/stellar-cso/issues"><img src="https://img.shields.io/github/issues/MakeMHz/stellar-cso.svg" alt="GitHub Issues"></a>
 <a href=""><img src="https://img.shields.io/badge/contributions-welcome-orange.svg" alt="Contributions welcome"></a>
 <a href="https://opensource.org/license/bsd-3-clause/"><img src="https://img.shields.io/github/license/MakeMHz/stellar-cso.svg?color=green" alt="License"></a>
</p>

I'll be using this repo to add features to the ciso script and flesh it out a bit more.

## Added features
- The ability to provide a directory path as an input argument, the script will process all .ISO files within that directory.
- The ability to scrub ISO files, zeroes out padding sectors and makes compression of Redump images more efficient.

## Usage
```bash
python3 ciso.py <ISO/XISO Path>
```
To enable ISO scrubbing/trimming:
```bash
python3 ciso.py -s <ISO/XISO Path>
```
or
```bash
python3 ciso.py --scrub <ISO/XISO Path>
```

## About

Compression script is based on, and forked, from [https://github.com/phyber/ciso](https://github.com/phyber/ciso) under the BSD-3-Clause license.

Based on ciso from [https://github.com/jamie/ciso](https://github.com/jamie/ciso).
