# REDACTED

The secret was hidden in plain sight: the PDF concealed text visually, but the text was still there to copy.

## The reveal

Open `TISC-26-091-SINGULARITY.pdf`, select everything with **Ctrl+A**, and paste it into a text editor. Among the hidden text fields is a suspicious Base64 string:

```text
VElTQ3tCUk8hUmVkYWN0UERGc1Byb3Blcmx5TGFoISEhfQ==
```

Decoding it gives the flag:

```text
TISC{BRO!RedactPDFsProperlyLah!!!}
```

The lesson is as short as the solve: hiding PDF text on screen does not remove it from the document.
