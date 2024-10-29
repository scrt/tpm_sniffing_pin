# Bitlocker TPM + PIN Decryptor

Simple Python PoC to retrieve the VMK through TPM Sniffing by knowing the user's PIN.

# Blog posts

Additonal details can be found on the following blogpost.

* https://blog.scrt.ch/2024/10/28/privilege-escalation-through-tpm-sniffing-when-bitlocker-pin-is-enabled/

## Install

```
pip install pycryptodome 
```

## Usage

The script takes three parameters: the user's PIN, the encrypted partition, and the buffer obtained from the unseal success message captured via TPM bus sniffing.

```
usage: tpm_sniffing_pin --dev [DEV] --pin [PIN] --tpm [TPM_BUFFER]

options:
  -h, --help  show this help message and exit
  --dev DEV   Bitlocker encrypted partition path
  --pin PIN   Bitlocker PIN code (6-20 digits)
  --tpm TPM   Buffer (160 hex-char) retrieved through TPM sniffing starting with "5000000005000000"
```
