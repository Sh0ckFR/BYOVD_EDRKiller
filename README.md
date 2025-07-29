# BYOVD EDRKiller

## Disclaimer
⚠️ This project is provided exclusively for educational purposes and is intended to be used only in authorized environments. You may only run or deploy this project on systems you own or have explicit, documented permission to test. Any unauthorized use of this project against systems without consent is strictly prohibited and may be illegal.

By using this project, you agree to use it responsibly and ethically. The author assumes no liability for misuse or any consequences arising from the use of this project.

# General

To practice Bring Your Own Vulnerable Driver (BYOVD) techniques covered in the CETP course, I set out to build an EDR-killer using a vulnerable driver that is not currently blocked by Microsoft's [recommended driver blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml) so I can load it on my latest W11 testing system with secure boot and HVCI enabled.

A well-known example, `truesight.sys` from Adlice (also listed on [LOLDDrivers](https://www.loldrivers.io/drivers/e0e93453-1007-4799-ad02-9b461b7e0398/)), is already blocked by Microsoft and will trigger an error explicitly stating that the driver is vulnerable when attempting to load it:

<img width="580" height="320" alt="Pasted image 20250727172458" src="https://github.com/user-attachments/assets/26a6202f-344f-4181-b82f-e4ac32073692" />

From [@d1rkmtr](https://x.com/d1rkmtr/status/1947664686897365177)'s tweet, another potentially useful vulnerable driver was shared, but like the newly indexed `BdApiUtil.sys` on LOLDDrivers, it fails to load on the latest Windows 11 versions. This behavior is due to HVCI (Hypervisor-Protected Code Integrity) and Secure Boot, not the driver blocklist. These protections enforce stricter requirements for driver signing and integrity, which unsigned or improperly signed drivers can't meet.

<img width="990" height="621" alt="Pasted image 20250727172100" src="https://github.com/user-attachments/assets/4ab894f9-0d4e-4cd1-9562-921487d3a500" />

Interestingly, the `wsftprm.sys` driver, listed on [LOLDDrivers](https://www.loldrivers.io/drivers/30e8d598-2c60-49e4-953b-a6f620da1371/), is not on Microsoft's blocklis and loads successfully on fully patched Windows 11 with Secure Boot and HVCI enabled. Its digital signature is valid and accepted by the system.

<img width="978" height="602" alt="Pasted image 20250727172206" src="https://github.com/user-attachments/assets/063a96d1-5f95-48d0-b897-55f2bbba1489" />

The vulnerability in this driver was discovered by [Northwave](https://northwave-cybersecurity.com/vulnerability-notice-topaz-antifraud), indicating that it could be used for a EDR-killer. Making it a viable candidate for further exploration and development of a proof-of-concept.

# Reversing the driver

Disclaimer: I am by no means an experienced reverse engineer. The vulnerability in this driver was already publicly known, and I did not discover it myself. Full credit for the original vulnerability research goes to [Northwave](https://northwave-cybersecurity.com/vulnerability-notice-topaz-antifraud).

The first step is to inspect the driver's import table and check whether it imports the following native APIs:
- `ZwOpenProcess`
- `ZwTerminateProcess` 

<img width="1278" height="560" alt="Pasted image 20250727143504" src="https://github.com/user-attachments/assets/26599ce6-2d5f-4af6-85cc-d800e05d1c79" />

If these functions are present, the next step is to cross-reference where they are called within the driver. This helps identify code paths that may open or terminate processes. While analyzing the references, I traced the usage of `ZwOpenProcess` and `ZwTerminateProcess` back to the driver's entry point, where they are ultimately invoked through the dispatch routine assigned to `MajorFunction[14]`, which corresponds to `IRP_MJ_DEVICE_CONTROL`.

This dispatch routine is implemented in the function `sub_140001540`.

<img width="772" height="408" alt="Pasted image 20250727144806" src="https://github.com/user-attachments/assets/7ad20e03-5907-4bf2-b356-2327aee72458" />

<img width="607" height="63" alt="Pasted image 20250727145950" src="https://github.com/user-attachments/assets/1e650696-1952-441f-b49b-e38f95171a70" />

The function is currently misidentified as handling `IRP_MJ_READ`, but based on the driver setup, we know it is actually a `IRP_MJ_DEVICE_CONTROL` (`MajorFunction[14]`). This function is a [driver dispatch routine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_dispatch), which means its prototype should conform to:

```c
NTSTATUS DriverDispatch(
  _In_ PDEVICE_OBJECT DeviceObject,
  _Inout_ PIRP Irp
);
```

So we can change the input parameters;

<img width="704" height="58" alt="Pasted image 20250727150140" src="https://github.com/user-attachments/assets/f510c45d-416e-49cd-9a66-7fe69e194761" />

As we've determined that this function handles `IRP_MJ_DEVICE_CONTROL` requests (not `IRP_MJ_READ`), several structure references need to be corrected. For example:

<img width="540" height="318" alt="Pasted image 20250727150317" src="https://github.com/user-attachments/assets/df7d5e1d-f8d0-4211-8387-a09378e3ee1e" />

<img width="611" height="330" alt="Pasted image 20250727150852" src="https://github.com/user-attachments/assets/b8f3ad16-71f6-420e-983a-7de42f242eed" />

Next, I revisited the `ZwTerminateProcess` import and found that it is called within the function `sub_140002848`. Inside this function, the flow is straightforward:
- `ZwOpenProcess` is first called to obtain a handle to the target process.
- If the handle is valid, `ZwTerminateProcess` is invoked to kill that process.

<img width="691" height="246" alt="Pasted image 20250727151547" src="https://github.com/user-attachments/assets/2e38142e-acfc-4fa1-95f8-e9616d4a13b7" />

<img width="582" height="477" alt="Pasted image 20250727151631" src="https://github.com/user-attachments/assets/0379ceb1-0d43-4913-a37d-181aa2cae206" />

<img width="533" height="337" alt="Pasted image 20250727151712" src="https://github.com/user-attachments/assets/959e9ced-4e5e-4cc9-a56b-203c0ae3dd7e" />

The function takes `a1` as input, which is passed into the fourth parameter of `ZwOpenProcess`. According to the [ZwOpenProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwopenprocess) prototype, the fourth argument is a pointer to a `_CLIENT_ID` structure, which specifies the process

```c
NTSYSAPI NTSTATUS ZwOpenProcess(
  [out]          PHANDLE            ProcessHandle,
  [in]           ACCESS_MASK        DesiredAccess,
  [in]           POBJECT_ATTRIBUTES ObjectAttributes,
  [in, optional] PCLIENT_ID         ClientId
);
```

We can change the parameters and structures to reflect this, I also renamed the function to `TerminateProcessByID`

<img width="547" height="348" alt="Pasted image 20250727163908" src="https://github.com/user-attachments/assets/6449abd7-85da-45d7-b272-9ffaaeadd2b8" />


`TerminateProcessByID` is called by `sub_14000264C` with a supplied buffer. I renamed the function to `BeforeTerminateProcessById`

<img width="589" height="214" alt="Pasted image 20250727163949" src="https://github.com/user-attachments/assets/d1e354d5-9e65-4c97-ba4d-a75d2e46a0ff" />

Next, I investigated how to trigger the functions `BeforeTerminateProcessById` and `TerminateProcessByPID`. With the help of ChatGPT, I discovered that it is invoked when a `DeviceIoControl` call is made with IOCTL `0x22201C` and when the input buffer is `1036` bytes.

<img width="846" height="379" alt="Pasted image 20250727164333" src="https://github.com/user-attachments/assets/90199904-df48-471e-91bf-a6785bb55320" />

To determine the IOCTL code being handled when `IOCTLCode2 == 4`, we need to walk backward from that comparison and calculate the corresponding value for the IOCTL code. The logic is as follows:

```
v8 = IOCTLCode - 0x222000            // IOCTL 0x222000
v9 = v8 - 4                          // IOCTL 0x222004
v10 = v9 - 4                         // IOCTL 0x222008
v11 = v10 - 16                       // IOCTL 0x222018
IOCTLCode2 == 4                      // IOCTL 0x22201C
```

<img width="891" height="377" alt="Pasted image 20250727165443" src="https://github.com/user-attachments/assets/e42a2ed9-1d3e-4998-8dfe-01bf5e221431" />

When we go back to `TerminateProcessByID` we can see that the first 4 bytes of the input buffer will be set within the `_CLIENT_ID` struct. Which is then passed into `ZwOpenProcess`.

<img width="733" height="350" alt="Pasted image 20250727164956" src="https://github.com/user-attachments/assets/a6545f9e-38a0-4a98-a70c-168535e2d269" />

This means that, of the `1036`-byte input buffer expected by the driver when handling IOCTL `0x22201C`, the first 4 bytes must contain the target Process ID. In C we can define this with the following example;

```
// Custom struct for the IOCT call
typedef struct _wsftprmKillBuffer {
    DWORD   dwPID;
    BYTE    bPadding[1032];
} wsftprmKillBuffer;
```

Back in the driver’s entry point, we can see that the symbolic link is created using the result of the `sub_140001410` function. This symbolic link is important because it defines the user accessible name under `\\DosDevices\\` that user mode applications will use to interact with the driver via `CreateFileW`.

<img width="759" height="422" alt="Pasted image 20250727170526" src="https://github.com/user-attachments/assets/0eeb75ef-9e5d-4802-bf47-e44b5dae94c2" />

These functions use XOR-encoded byte sequences to obfuscate the symbolic link name. In the case of this driver, the function `sub_140001410` performs the decryption at runtime.

<img width="462" height="454" alt="Pasted image 20250727170610" src="https://github.com/user-attachments/assets/bb42e560-b476-4879-9a68-1c8e8b84901c" />

ChatGPT successfully decrypted the obfuscated symbolic link string as: `\\DosDevices\\Warsaw_PM`. This was the final missing piece needed to fully interact with the driver and begin building our EDRKiller.

## Summary of Key Details
-  **Device Name:** `\\DosDevices\\Warsaw_PM`  
	  - Accessed from user-mode as `\\\\.\\Warsaw_PM`)
- **IOCTL Code:** `0x22201C`  (Triggers the vulnerable process termination routine)
- **Expected Input Buffer:**
    - **Size:** `1036` bytes
    - **Format:** The first 4 bytes represent the target PID as a `DWORD`

```
typedef struct _wsftprmKillBuffer {
    DWORD   dwPID;
    BYTE    bPadding[1032];
} wsftprmKillBuffer;
```

# Proof of Concept

This `C` project includes a proof-of-concept (POC) that enumerates EDR-related processes and repeatedly sends the vulnerable `IOCTL` to terminate them in a loop, continuing until the user presses `q` to exit.

#### EDR's
Currently, the targeted EDR solutions and associated processes are:
- Microsoft Defender Antivirus
- Microsoft Defender for Endpoint
- Elastic EDR
- Sysmon

#### What does it do
- Writes vulnerable driver to `C:\Windows\System32\Drivers\<FILE>` and loads the driver (Configurable in `settings.h`)
- Keeps looping and enumerating EDR Processes
- Kills EDR Process using the IOCTL of the vulnerable driver
- Exits when q is pressed
- Unloads the vulnerable driver and removes the file from `C:\Windows\System32\Drivers\<FILE>`

#### Test
The testing environment has Secure Boot, Virtualization-Based Security (VBS), and Hypervisor-Protected Code Integrity (HVCI) enabled. These mitigations were verified using my [EnumMitigations](https://github.com/0xJs/EnumMitigations) tool.

<img width="720" height="222" alt="Pasted image 20250727190301" src="https://github.com/user-attachments/assets/8e772084-4d4b-45da-8407-7d3386554f86" />

<img width="1553" height="900" alt="Pasted image 20250727190532" src="https://github.com/user-attachments/assets/38fbdfab-2ddc-409b-bb5f-c387255484e2" />


#### Cleanup
- The payload should unload and remove the driver. If it didn't then manually remove it

```
sc stop wsftprm
sc delete wsftprm
del C:\Windows\System32\Drivers\wsftprm.sys
```
