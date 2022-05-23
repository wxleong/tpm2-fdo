# Introduction

TPM enabled FIDO Device Onboard (FDO) guide.

# Table of Contents

- **[Prerequisites](#prerequisites)**
- **[Device Set Up](#device-set-up)**
- **[Services Set Up](#services-set-up)**
- **[Execute FDO Protocols](#execute-fdo-protocols)**
- **[Execute Resale Protocol](#execute-resale-protocol)**
- **[References](#references)**
- **[License](#license)**

# Prerequisites

- Raspberry Pi 4 Model B with TPM 2.0. Prepare the OS image according to [[1]](#1)
- Install tpm2-tss, tpm2-tools, and tpm2-tss-engine according to [[1]](#1)
- Install the following:
    ```
    $ sudo apt install cmake maven openjdk-9-jre
    ```

# Device Set Up

Summary of [[3]](#3).

Install dependencies:
```
$ git clone https://github.com/intel/safestringlib ~/safestringlib
$ cd ~/safestringlib
$ git checkout v1.0.0
$ mkdir obj
$ make

$ git clone https://github.com/intel/tinycbor ~/tinycbor
$ cd ~/tinycbor
$ git checkout v0.5.3
$ make
```

Environment set up:
```
$ export SAFESTRING_ROOT=~/safestringlib
$ export TINYCBOR_ROOT=~/tinycbor
$ export OPENSSL_ENGINES=/usr/lib/arm-linux-gnueabihf/engines-1.1/
$ sudo chmod a+rw /dev/tpmrm0
```

Build client SDK:
```
$ git clone https://github.com/secure-device-onboard/client-sdk-fidoiot ~/client-sdk-fidoiot
$ cd client-sdk-fidoiot
$ git checkout v1.1.0

# Apply patch
$ git clone https://github.com/wxleong/tpm2-fdo ~/tpm2-fdo
$ git am < ~/tpm2-fdo/patch/compile-error-fix.patch
$ git am < ~/tpm2-fdo/patch/tpm2-tss-engine-path-fix.patch

# Set manufacturer address
$ echo -n http://localhost:8039 > data/manufacturer_addr.bin

# Set the maximum ServiceInfo Size
$ echo -n 8192 > data/max_serviceinfo_sz.bin

# Set the device serial number
$ echo -n serial-01 > data/manufacturer_sn.bin

# Set the device model number
$ echo -n model-01 > data/manufacturer_mod.bin

# Use TPM
$ cmake -DDA=tpm20_ecdsa256 -DTPM2_TCTI_TYPE=tpmrm0 .
$ make -j$(nproc)
```
<!--
# Set REUSE feature to reuse the same ownership voucher
$ cmake -DREUSE=true

# Use tpm2-abrmd
$ cmake -DDA=tpm20_ecdsa256 .

# Use in-kernel resource manager /dev/tpmrm0
$ cmake -DDA=tpm20_ecdsa256 -DTPM2_TCTI_TYPE=tpmrm0 .
-->

Provision TPM:
```
$ cd ~/client-sdk-fidoiot
$ tpm2_clear -c p
$ tpm2_createprimary -C e -g sha256 -G ecc256:aes128cfb -c data/tpm_primary_key.ctx
$ tpm2_evictcontrol -C o 0x81000001 -c data/tpm_primary_key.ctx
$ tpm2tss-genkey -a ecdsa -c nist_p256 data/tpm_ecdsa_priv_pub_blob.key -v -P 0x81000001
```

Generate CSR:
```
$ openssl req -new -engine tpm2tss -keyform engine -outform DER -out data/tpm_device_csr -key data/tpm_ecdsa_priv_pub_blob.key -subj "/CN=sdo-tpm-device" -verbose
```

<!--
Seems like the data/device_mstring is not used at all?
Instead the MString info is taken from:
- key type id: is hardcoded in client-sdk-fidoiot/lib/m-string.c: key_id = `FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256;`
- serial number: data/manufacturer_sn.bin
- model number: data/manufacturer_mod.bin
- csr: data/tpm_device_csr

Generate Device MString: 
```
$ cd ~/client-sdk-fidoiot
$ openssl req -new -engine tpm2tss -keyform engine -out data/device_mstring -key data/tpm_ecdsa_priv_pub_blob.key -subj "/CN=www.fdoDevice1.intel.com" -verbose; truncate -s -1 data/device_mstring; echo -n "13" > /tmp/m_string.txt; truncate -s +1 /tmp/m_string.txt; echo -n "intel-1234" >> /tmp/m_string.txt; truncate -s +1 /tmp/m_string.txt; echo -n "model-123456" >> /tmp/m_string.txt; truncate -s +1 /tmp/m_string.txt; cat data/device_mstring >> /tmp/m_string.txt; base64 -w 0 /tmp/m_string.txt > data/device_mstring; rm -f /tmp/m_string.txt
```
<!--
<!--
MString syntax:
[<key type id>, <serial number>, <model number>, <CSR>]
It is used to form DeviceMfgInfo
-->

# Services Set Up

Build manufacturer, rendezvous, owner, and reseller services:
```
$ git clone https://github.com/secure-device-onboard/pri-fidoiot ~/pri-fidoiot
$ cd ~/pri-fidoiot
$ git checkout v1.1.0
$ mvn clean install
$ ls ~/pri-fidoiot/component-samples/demo/
```

# Execute FDO Protocols

Summary of [[4]](#4)[[5]](#5)[[6]](#6).

<!--
You may start an all-in-one service instead of starting it individually:
```
$ cd ~/pri-fidoiot/component-samples/demo/aio
$ java -jar aio.jar
```
-->

1. Start services:<br>

    <!--
    Find the individual server config file at ~/pri-fidoiot/component-samples/demo/x/service.yml
    -->

    Start manufacturer service (https://localhost:8038, http://localhost:8039):
    ```
    $ cd ~/pri-fidoiot/component-samples/demo/manufacturer
    $ java -jar aio.jar
    ```
    > - Deleting `~/pri-fidoiot/component-samples/demo/manufacturer/app-data` will force the service to reinitialize the database.

    Start rendezvous service (http://localhost:8040, https://localhost:8041):
    ```
    $ cd ~/pri-fidoiot/component-samples/demo/rv
    $ java -jar aio.jar
    ```
    > - Deleting `~/pri-fidoiot/component-samples/demo/rv/app-data` will force the service to reinitialize the database.

    Start owner service (http://localhost:8042, https://localhost:8043):
    ```
    $ cd ~/pri-fidoiot/component-samples/demo/owner
    $ java -jar aio.jar
    ```
    > - Deleting `~/pri-fidoiot/component-samples/demo/owner/app-data` will force the service to reinitialize the database.

2. Device Initialize Protocol (DI):<br> 

    Configure manufacturer service's RendezvousInfo:
    ```
    $ curl -d \
    "[[[5,\"localhost\"],[3,8041],[12,2],[2,\"localhost\"],[4,8041]]]" \
    -H "Content-Type: text/plain" \
    --digest -u apiUser:"" \
    -X POST \
    http://localhost:8039/api/v1/rvinfo
    ```
    > The RendezvousInfo is based on [[7]](#7):
    > - `[[[5, RVDns], [3, RVDevPort], [12, RVProtocol], [2, RVIPAddress], [4, RVOwnerPort]]]`
    > - The RendezvousInfo type indicates the manner and order in which the Device and Owner find the Rendezvous Server. It is configured during manufacturing (e.g., at an ODM), so the manufacturing entity has the choice of which Rendezvous Server(s) to use and how to access it or them.
    > - The value for api_user is present in `~/pri-fidoiot/component-samples/demo/manufacturer/service.yml` file and value for api_password is present in `~/pri-fidoiot/component-samples/demo/manufacturer/service.env` file.

    Execute the DI protocol ([client log](log/protocol_DI_client.log), [manufacturer log](log/protocol_DI_manufacturer.log)) and record down the GUID and serial number:
    ```
    $ cd ~/client-sdk-fidoiot
    $ ./build/linux-client
    ```
    > - An Ownership Voucher will be created and store on manufacturer service
    > - A TPM backed HMAC key is created and stored on device `~/client-sdk-fidoiot/data/tpm_hmac_data_priv.key`.
    > - Deleting `~/client-sdk-fidoiot/data/Normal.blob` file will force the device to re-run DI protocol.
    <!--
    During DI protocol (DISetCredentials, Type 11), the RendezvousInfo is set to OVHeader which stores in the device Normal.blob. This is how the device learn about rendezvous url.
    -->

3. Extension of the Ownership Voucher:<br>

    Get owner certificate:
    ```
    $ curl \
    --digest -u apiUser:"" \
    http://localhost:8042/api/v1/certificate?alias=SECP256R1 \
    > ~/owner.crt
    ```
    > - The value for api_user is present in `~/pri-fidoiot/component-samples/demo/owner/service.yml` file and value for api_password is present in `~/pri-fidoiot/component-samples/demo/owner/service.env` file.

    Extension of the Ownership Voucher, from manufacturer to a new owner:
    ```
    $ curl --data-raw "`cat ~/owner.crt`" \
    -H "Content-Type: text/plain" \
    --digest -u apiUser:"" \
    -X POST \
    http://localhost:8039/api/v1/mfg/vouchers/${serial_number} \
    > ~/extended-voucher.txt
    ```
    > - In this example, the serial_number is serial-01.

4. Transfer Ownership Protocol 0 (TO0):<br>

    Upload the extended Ownership Voucher to owner:
    ```
    $ curl --data-raw "`cat ~/extended-voucher.txt`" \
    -H "Content-Type: text/plain" \
    --digest -u apiUser:"" \
    -X POST \
    http://localhost:8042/api/v1/owner/vouchers
    ```
    > - Returns a list of registered Ownership Voucher:
    >   ```
    >   $ curl \
    >     --digest -u apiUser:"" \
    >     http://localhost:8042/api/v1/owner/vouchers
    >   ```

    Configure owner service's RVTO2Addr:
    ```
    $ curl -d \
    "[[\"localhost\",\"localhost\",8043,5]]" \
    -H "Content-Type: text/plain" \
    --digest -u apiUser:"" \
    -X POST \
    http://localhost:8042/api/v1/owner/redirect
    ```
    > The RVTO2Addr is based on [[8]](#8):
    > - `[[RVIP, RVDNS, RVPort, RVProtocol]]`
    > - The RVTO2Addr indicates to the Device how to contact the Owner to run the TO2 protocol. The RVTO2Addr is transmitted by the Owner to the Rendezvous Server during the TO0 protocol, and conveyed to the Device during the TO1 protocol.

    Execute the TO0 protocol ([owner log](log/protocol_TO0_owner.log), [rendezvous log](log/protocol_TO0_rendezvous.log)):
    ```
    $ curl \
    --digest -u apiUser:"" \
    http://localhost:8042/api/v1/to0/${device_guid}
    ```
    > An example of device_guid: 30a9dbe4-206c-47e3-8c43-a18abba63697

5. **Optional step.** ServiceInfo and Management Service - Agent Interactions:<br>
    
    <!--
    In this approach we fetch the resource from a URL.

    [Optional] Configure the owner ServiceInfo [[9]](#9) package. The example given here is to execute a custom script:
    ```
    $ curl --data-raw \
    '[{"filedesc" : "setup.sh","resource" : "https://github.com/wxleong/tpm2-fdo/raw/develop-genesis/script/setup.sh/token=.....?????"}, {"exec" : ["/usr/bin/bash","setup.sh"] }]' \
    -H "Content-Type: text/plain" \
    --digest -u apiUser:"" \
    -X POST \
    http://localhost:8042/api/v1/owner/svi
    ```
    > This is based on [[10]](#10):
    > - `'[{"filedesc" : "setup.sh","resource" : "https://github.com/wxleong/tpm2-fdo/raw/develop-genesis/script/setup.sh"}, {"exec" : ["/usr/bin/bash","setup.sh"] }]'` means, fetch the content of "setup.sh" from the resource link then execute it.
    -->

    <!--
    In this appraoch we fetch the resource from the service database SYSTEM_RESOURCE table.
    -->
    Configure the owner service's ServiceInfo [[9]](#9) package. The example given here will execute a [custom script](script/setup.sh) on the client platform:
    ```
    # Upload a script to the owner service
    $ curl --data-binary \
    '@/home/pi/tpm2-fdo/script/setup.sh' \
    -H "Content-Type: text/plain" \
    --digest -u apiUser:"" \
    -X POST \
    http://localhost:8042/api/v1/owner/resource?filename=setup-script

    # Configure the ServiceInfo
    $ curl --data-raw \
    '[{"filedesc" : "setup.sh","resource" : "setup-script"}, {"exec" : ["/usr/bin/bash","setup.sh"] }]' \
    -H "Content-Type: text/plain" \
    --digest -u apiUser:"" \
    -X POST \
    http://localhost:8042/api/v1/owner/svi
    ```
    > This is based on [[10]](#10):
    > - `'[{"filedesc" : "setup.sh","resource" : "setup-script"}, {"exec" : ["/usr/bin/bash","setup.sh"] }]'` translates to download the resource "setup-script" and store it as "setup.sh" on the client platform, and subsequently run the "setup.sh" with a bash shell.
    <!--
    The owner side:
    The string is parsed to: pri-fidoiot\protocol\src\main\java\org\fidoalliance\fdo\protocol\db\FdoSysInstruction.java
    The FdoSysInstruction will be processed in pri-fidoiot\protocol\src\main\java\org\fidoalliance\fdo\protocol\db\FdoSysOwnerModule.java

    The client side:
    The setup.sh will be downloaded to the device and it will be executed in client-sdk-fidoiot\device_modules\fdo_sys\sys_utils_linux.c. A fork will happen to create a child process to execute the script with execv("/usr/bin/bash", ".../setup.sh"). The parent process will keep track of the child.
    "filedesc" cannot contain path, hence, the file will be downloaded to your current workspace. Check out the is_valid_filename() method in client-sdk-fidoiot\device_modules\fdo_sys\sys_utils_linux.c.
    "exec" can contain path.
    -->

6. Transfer Ownership Protocol 1&2 (TO1 & TO2):<br>

    Execute the TO1 and TO2 protocol:
    ```
    $ cd ~/client-sdk-fidoiot
    $ ./build/linux-client
    ```
    > Sample logs:
    > - Without custom ServiceInfo:
    >   - [Client log](log/protocol_TO1_TO2_wo_si_client.log)
    >   - [Rendezvous log](log/protocol_TO1_TO2_wo_si_rendezvous.log)
    >   - [Owner log](log/protocol_TO1_TO2_wo_si_owner.log)
    > - With custom ServiceInfo:
    >   - [Client log](log/protocol_TO1_TO2_w_si_client.log)
    >   - [Rendezvous log](log/protocol_TO1_TO2_w_si_rendezvous.log)
    >   - [Owner log](log/protocol_TO1_TO2_w_si_owner.log)

# Execute Resale Protocol

To-do.

<!--
on owner service, use the resell endpoint to obtain an extended ownership voucher (i.e., ~/extended-voucher.txt), for demonstration purpose, use the same owner as the new owner, so read the certificate from the owner service. After obtaining the new extended ownership voucher, restart the whole process again, starting from "Upload the extended Ownership Voucher to owner:..."
-->

<!--
Reseller service:
- https://github.com/secure-device-onboard/pri-fidoiot/tree/master/component-samples/demo/reseller
- An important endpoint is not documented: /api/v1/certificate/*. This endpoint is similar to the owner endpoints to manage the owner certificate/key. You can use it to retrieve the reseller service certificate. Manufacturer may extend the Ownership Voucher using the reseller certificate.
- This service is somewhat similar to the Owner service. Using the reseller endpoint you can extend Ownership Voucher to a new owner (aka reseller). Basically the reseller service is acting as an intermediate so manufacturer can be relieved after producing the product.
- If you are using the owner service, reseller service is not necessary. Owner service has resell endpoint too (i.e., /api/v1/resell/{guid})
-->

# References

<a id="1">[1] https://github.com/wxleong/tpm2-rpi4</a> <br>
<a id="2">[2] https://github.com/secure-device-onboard/client-sdk-fidoiot/blob/master/docs/tpm.md</a> <br>
<a id="3">[3] https://github.com/secure-device-onboard/pri-fidoiot</a> <br>
<a id="4">[4] https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/manufacturer/README.md</a> <br>
<a id="5">[5] https://github.com/secure-device-onboard/pri-fidoiot/tree/master/component-samples/demo/rv/README.md</a> <br>
<a id="6">[6] https://github.com/secure-device-onboard/pri-fidoiot/tree/master/component-samples/demo/owner/README.md</a> <br>
<a id="7">[7] https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.0-20201202.html#RVInfo</a> <br>
<a id="8">[8] https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.0-20201202.html#rvto2addr</a> <br>
<a id="9">[9] https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.0-20201202.html#management-agent-service-interactions-using-serviceinfo</a> <br>
<a id="10">[10] https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.0-20201202.html#ServiceInfo</a> <br>

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
