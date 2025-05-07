
# Guide to Configuring Environment Variables

This tool requires two API keys to function properly. These API keys are used to interact with the **OTX (AlienVault)** and **VirusTotal** services. To ensure the program works correctly, you need to configure two environment variables on your operating system. Below are instructions for doing so on Windows, macOS, and Linux.

## Required Environment Variables

1. **IPCHECKER_OTX_API_KEY**: The API key for the **OTX (AlienVault)** service.
2. **IPCHECKER_VIRUSTOTAL_API_KEY**: The API key for the **VirusTotal** service.

## How to Set Environment Variables

### On Windows

#### Setting Temporary Environment Variables (only for the current session)

1. Open **CMD** (Command Prompt) or **PowerShell**.
2. Run the following commands to temporarily set the environment variables:

   In **CMD**:
   ```cmd
   set IPCHECKER_OTX_API_KEY=your_api_key_here
   set IPCHECKER_VIRUSTOTAL_API_KEY=your_api_key_here
   
   python ipchecker.py <IPV4_TO_CHECK_HERE>
      or using executable file with
   cd dist
   .\ipchecker.exe <IPV4_TO_CHECK_HERE>
   ```

   In **PowerShell**:
   ```powershell
   $env:IPCHECKER_OTX_API_KEY="your_api_key_here"
   $env:IPCHECKER_VIRUSTOTAL_API_KEY="your_api_key_here"

   python ipchecker.py <IPV4_TO_CHECK_HERE>
      or using executable file with
   cd dist
   .\ipchecker.exe <IPV4_TO_CHECK_HERE>
   ```

   *Note: The environment variables set this way will be available only in the current terminal session.*

#### Setting Permanent Environment Variables

1. Go to **Control Panel** > **System** > **Advanced system settings**.
2. Click on **Environment Variables**.
3. Under "User variables" or "System variables", click **New...** and add the following variables:

   - Variable name: `IPCHECKER_OTX_API_KEY`, Variable value: `your_api_key_here`
   - Variable name: `IPCHECKER_VIRUSTOTAL_API_KEY`, Variable value: `your_api_key_here`

4. After adding the variables, click **OK** to save the changes.
5. Close and reopen the terminal or IDE to load the new environment variables.

---

### On macOS and Linux

#### Setting Temporary Environment Variables (only for the current session)

1. Open the **Terminal**.
2. Run the following commands to temporarily set the environment variables:

   ```bash
   export IPCHECKER_OTX_API_KEY="your_api_key_here"
   export IPCHECKER_VIRUSTOTAL_API_KEY="your_api_key_here"


   python3 ipchecker.py <IPV4_TO_CHECK_HERE>
      or using executable file with
   cd dist
   ./ipchecker <IPV4_TO_CHECK_HERE>
   ```

   *Note: The environment variables set this way will be available only for the current terminal session.*

#### Setting Permanent Environment Variables

To make the environment variables permanent, you need to add them to your shell's configuration file.

1. Open the terminal and edit your shell's configuration file. For example, if you use **bash**, edit the `~/.bashrc` file:

   ```bash
   nano ~/.bashrc
   ```

   If you use **zsh** (e.g., on macOS), edit the `~/.zshrc` file:

   ```bash
   nano ~/.zshrc
   ```

2. Add the following lines to the end of the file:

   ```bash
   export IPCHECKER_OTX_API_KEY="your_api_key_here"
   export IPCHECKER_VIRUSTOTAL_API_KEY="your_api_key_here"
   ```

3. Save and close the file (`Ctrl + X`, then press `Y` to confirm).
4. Reload the configuration file to apply the changes:

   ```bash
   source ~/.bashrc  # for bash
   ```

   or

   ```bash
   source ~/.zshrc  # for zsh
   ```

---

## How to Verify That the Environment Variables Are Set Correctly

After setting the environment variables, you can verify their correct functionality by running the following Python script:

```python
import os

IPCHECKER_OTX_API_KEY = os.getenv("IPCHECKER_OTX_API_KEY")
IPCHECKER_VIRUSTOTAL_API_KEY = os.getenv("IPCHECKER_VIRUSTOTAL_API_KEY")

if not IPCHECKER_OTX_API_KEY or not IPCHECKER_VIRUSTOTAL_API_KEY:
    print("⚠️ Error: One or both of the API keys are not set.")
else:
    print("✅ API keys are successfully set.")
```

If the variables are set correctly, you should see the message:

```
✅ API keys are successfully set.
```

---

## Troubleshooting

If you encounter errors while running the tool, check that the environment variables are set correctly. You can do this by running the following command in the terminal:

### On Windows (CMD):
```cmd
echo %IPCHECKER_OTX_API_KEY%
echo %IPCHECKER_VIRUSTOTAL_API_KEY%
```

### On macOS/Linux:
```bash
echo $IPCHECKER_OTX_API_KEY
echo $IPCHECKER_VIRUSTOTAL_API_KEY
```

If the variables do not print their values, it means they are not set correctly.

---

If you have any questions or need assistance, feel free to contact me!
