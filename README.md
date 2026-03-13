# STFCF Software Pack

![tag](https://img.shields.io/badge/tag-2.0.0-brightgreen.svg)
[![release note](https://img.shields.io/badge/release_note-view_html-gold.svg)](https://htmlpreview.github.io/?https://github.com/STMicroelectronics/stm32-mw-stfcf/blob/hal2/Release_Notes.html)


## Overview

The STM32 Flexible Crypto Framework (STFCF) is designed to provide an easy access to the cryptographic offer by STMicroelectronics.

## Description

STFCF is an STMicroelectronics initiative providing users with several crypto implementations in a flexible way by configuring the required algorithm and implementation.

The following implementations are supported:
  - MbedTLS ALT for HAL
  - MbedTLS ALT for STCryptoLib
  - MbedTLS
  - Key Wrapping Engine (KWE)

## Usage

The high level interface of the STFCF is the Platform Security Architecture Application Programming Interface (PSA API).

> NOTE: It depends directly to the PSA API implementation of the Mbed TLS middleware.

STFCF provides configuration files to select cryptographic algorithms and implementations in addition to Mbed TLS flags.

