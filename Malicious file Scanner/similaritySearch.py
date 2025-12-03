def findSimilarity(fileHash):
    try:
        with open('hashes.txt', 'r') as file:
            lines = file.readlines()
            
            cleaned_lines = [line.strip() for line in lines]
        b1 = bytes.fromhex(fileHash)
        
        for hash in cleaned_lines:
            try:
                b2 = bytes.fromhex(hash)
    # Truncate to the shorter length
                min_len = min(len(b1), len(b2))
                b1 = b1[:min_len]
                b2 = b2[:min_len]
                
                # XOR byte by byte
                xor_result = [b1[i] ^ b2[i] for i in range(min_len)]
                
                # Count number of differing bits
                total_bits = min_len * 8;
                differing_bits = sum(bin(byte).count('1') for byte in xor_result)
                # rank = tlsh.diff(hash,fileHash)
                rank = (1 - (differing_bits/total_bits))*100
                
                if(rank>=70):
                    print(rank)
                    return True
            except Exception as e:
                # print("Exception occured while comparing hash: "+str(e))
                continue

    
    except Exception as e:
        print("Exception occured while finding similarity: "+str(e))