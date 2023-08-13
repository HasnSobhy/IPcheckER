# IP Reputation Assessment Tool

This tool is designed to facilitate the assessment of the reputation of a given list of IP addresses across multiple threat intelligence sources. Its primary function is to generate comprehensive reports for any specified IP address, providing valuable insights into its potential threat level.

## Features

- Evaluate the reputation of IP addresses using various threat intelligence sources.
- Generate detailed reports for each IP address, including threat indicators and risk assessment.
- Easy-to-use command-line interface for interacting with the tool.
- Customize the sources used for reputation assessment based on your requirements.

## Installation

1. Clone this repository:

   ```bash
   git clone git@github.com:HasnSobhy/IPcheckER.git
   cd IPcheckER
   pip install -r requirements.txt

2. ## Note:

To perform the scanning process, it is necessary to adhere to the following formal instructions:
  
    a- Ensure that you have the "ips.txt" file available in the current directory. If the file does not exist, create it in the current directory.
    
    b- Open the "ips.txt" file using a text editor of your choice.
    
    c- Add all the IP addresses that you want to scan into the "ips.txt" file. Each IP address should be listed on a separate line.
    
    d- Save and close the "ips.txt" file after adding all the IP addresses.
  
  By following these instructions, you will have the "ips.txt" file in the current directory, containing all the IP addresses that need to be scanned. 

## Usage
  You must add ips.txt in the currunt directory and add all IPs in it for scanning it
  python IPchecER.py


## Contributing

Contributions are welcome! If you find a bug or want to enhance the tool's functionality, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

Feel free to customize this template further to match the specifics of your repository and tool. Also, ensure that you have an appropriate license file in your repository if you choose to use the MIT License or any other license.
