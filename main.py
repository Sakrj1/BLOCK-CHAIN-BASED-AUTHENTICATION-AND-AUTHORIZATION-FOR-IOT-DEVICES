from fastapi import FastAPI, HTTPException
from web3 import Web3
from pydantic import BaseModel, Field, validator
import os,  json
from dotenv import load_dotenv
from eth_hash.auto import keccak as keccak_256
from web3.middleware import geth_poa_middleware
import time
import psutil


# Load environment variables from .env file
load_dotenv()

# Connect to an Ethereum node
ganache_url ="http://127.0.0.1:7545"
# ganache_url = "https://alfajores-forno.celo-testnet.org"
w3 = Web3(Web3.HTTPProvider(ganache_url))

# Add PoA middleware to handle PoA-specific data
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

# Import Ethereum account from private key
private_key = os.getenv('PRIVATE_KEY')
print("Private Key: ", private_key)
account = w3.eth.account.from_key(private_key)

# Set default account for transactions
w3.eth.defaultAccount = account.address

# Check if the account is recognized by the node
if w3.eth.get_balance(account.address) is None:
    raise Exception('Account not recognized by the node')

# Load smart contract ABI and address
contract_address = w3.to_checksum_address(os.getenv('CONTRACT_ADDRESS'))
with open('abi.json') as f:
    contract_abi = json.load(f)
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Time used to deploy the contract
start_time = time.time()


# Function to send a signed transaction
def send_transaction(contract_instance, contract_function_name, *args):
    print("Account address: ", account.address)
    contract_function = getattr(contract_instance.functions, contract_function_name)
    nonce = w3.eth.get_transaction_count(account.address)
    tx_hash = contract_function(*args).transact({
        'from': account.address,
        'nonce': nonce,
        'gas': 1000000,
        'gasPrice': w3.to_wei('1', 'gwei'),
    })
    w3.eth.wait_for_transaction_receipt(tx_hash)
    # Get the transaction receipt
    receipt = w3.eth.get_transaction_receipt(tx_hash)

    # Get the gas used by the transaction
    gas_used = receipt['gasUsed']

    # Get the gas price
    gas_price = w3.eth.get_transaction(tx_hash)['gasPrice']

    # Calculate the cost
    cost = gas_used * gas_price
    print(f"Transaction sent with hash {tx_hash.hex()}. Cost: {cost} wei")
    return tx_hash

end_time = time.time()

print("Time taken to deploy contract: ", end_time - start_time)

# CPU usage
cpu_usage = psutil.cpu_percent()
print("CPU Usage: ", cpu_usage)

# RAM usage
ram_usage = psutil.virtual_memory()
print("RAM Usage: ", ram_usage)

# Disk usage
disk_usage = psutil.disk_usage('/')
print("Disk Usage: ", disk_usage)

app = FastAPI()

class DeviceInfo(BaseModel):
    serial_number: str = Field(..., description="Serial number of the device")
    mac_address: str = Field(..., description="MAC address of the device")
    model_number: str = Field(..., description="Model number of the device")
    device_id: str = Field(..., description="Unique identifier of the device")

    @validator("serial_number", "mac_address", "model_number", "device_id")
    def validate_length(cls, v):
        if len(v) > 255:
            raise ValueError("Field length exceeds maximum limit of 255 characters")
        return v

@app.post("/register_device")
async def register_device(device_info: DeviceInfo):
    try:
        # Register the device and store metadata on the blockchain
        tx_hash = send_transaction(contract, "registerDevice", device_info.serial_number, device_info.mac_address, device_info.model_number, device_info.device_id)

        # Generate the hashed ID so as to be able to return the hashed id with the return statement, though is is not a must
        unique_id_str = device_info.serial_number + device_info.mac_address + device_info.model_number
        hashed_id = Web3.keccak(text=unique_id_str).hex()
        
        return {"status": "Device registered successfully", "transaction_hash": tx_hash.hex(), "Hashed_id": hashed_id}
    except Exception as e:
        error_message = str(e)
        # Log the error message for debugging
        print(f"Error during registration: {error_message}")
        raise HTTPException(status_code=500, detail="Device registration failed")



@app.get("/get_device_metadata")
async def get_device_metadata(hashed_id:  str = None):
    if not hashed_id:
        raise HTTPException(status_code=400, detail="Missing required parameter: hashed_id")
    try:
        print(f"Received hashed_id: {hashed_id}")
        print("Received hashedID Type: ", type(hashed_id))

        hashed_id_bytes32 = Web3.to_bytes(hexstr=hashed_id) 
        # hashed_id_bytes32 = Web3.to_hex(hashed_id_bytes32)   # Convert it back to a standard HEX
        
        print("HashedID: ", hashed_id_bytes32)
        print("HashedID Type: ", type(hashed_id_bytes32))

        # Get the device metadata from the blockchain using the hashed ID
        device_metadata = contract.functions.getDeviceMetadata(hashed_id_bytes32).call()
        print("Device Metadata: ", device_metadata)

        # Parse the returned metadata
        hashed_device_id, serial_number, mac_address, model_number, device_id, authorized = device_metadata

        return {
            "hashed_device_id": hashed_device_id.hex(),
            "serial_number": serial_number,
            "mac_address": mac_address,
            "model_number": model_number,
            "device_id": device_id,
            "authorized": authorized
        }
    except Exception as e:
        error_message = str(e)
        print(f"Error retrieving device metadata: {error_message}")
        if 'Device not registered' in error_message:
            raise HTTPException(status_code=404, detail="Device not registered")
        else:
            raise HTTPException(status_code=500, detail="Failed to retrieve device metadata")


@app.post("/authorize_device")
async def authorize_device(hashed_id: str):
    try:
        print(f"Received hashed_id: {hashed_id}")
        hashed_id_bytes32 = Web3.to_bytes(hexstr=hashed_id) 
        # hashed_id_bytes32 = Web3.to_hex(hashed_id_bytes32)   # Convert it back to a standard HEX
        print("Hashedid: ", hashed_id_bytes32)
        print("HashedID Type: ", type(hashed_id_bytes32))
        # Authorize the device using hashed ID
        tx_hash = send_transaction(contract, 'authorizeDevice', hashed_id_bytes32)
        return {"status": "Device authorized", "transaction_hash": tx_hash.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/deauthorize_device")
async def deauthorize_device(hashed_id: str):
    try:
        hashed_id_bytes32 = Web3.to_bytes(hexstr=hashed_id) 
        # hashed_id_bytes32 = Web3.to_hex(hashed_id_bytes32)   # Convert it back to a standard HEX
        # Deauthorize the device using hashed ID
        tx_hash = send_transaction(contract, 'deauthorizeDevice', hashed_id_bytes32)
        return {"status": "Device deauthorized", "transaction_hash": tx_hash.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def hash_unique_id(value: str) -> str:
    """
    Hash the given value using keccak256 (SHA-3).

    Args:
        value (str): The value to be hashed.

    Returns:
        bytes32: The hashed value.
    """
    value_bytes = value.encode('utf-8')
    hashed_value = keccak_256(value_bytes)
    return hashed_value.hex()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
