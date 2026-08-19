from fastecdsa.point import Point
from fastecdsa.curve import secp256k1

def hex_to_point(pk_hex):
    try:
        # Clean up any whitespace or capitalization issues
        pk_hex = pk_hex.strip().lower()
        
        # Uncompressed public keys must be 130 hex characters long (65 bytes)
        if len(pk_hex) != 130:
            print(f"Skipping: Key length is {len(pk_hex)} characters (expected 130 for uncompressed)")
            return None
            
        # Uncompressed keys must start with the '04' prefix
        if not pk_hex.startswith("04"):
            print(f"Skipping: Key does not start with '04' prefix: {pk_hex[:4]}...")
            return None
            
        # Slice the hex string:
        # pk_hex[0:2]   -> '04' (prefix)
        # pk_hex[2:66]  -> X coordinate (64 hex characters / 32 bytes)
        # pk_hex[66:130] -> Y coordinate (64 hex characters / 32 bytes)
        x_str = pk_hex[2:66]
        y_str = pk_hex[66:130]
        
        # Convert hex strings directly to integers
        x = int(x_str, 16)
        y = int(y_str, 16)
        
        # Return the valid Curve Point
        return Point(x, y, secp256k1)
        
    except ValueError as ve:
        print(f"Mathematical validation failed for key: {pk_hex[:10]}... Error: {ve}")
        return None
    except Exception as e:
        print(f"Unexpected error parsing key: {e}")
        return None
