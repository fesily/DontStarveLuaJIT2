with open(R".lua", "rb") as f:
    encrypted_content = f.read()

part1 = encrypted_content[:7997] 
part2 = encrypted_content[7997:]

swapped_content = part2 + part1

part2_reversed = part2[::-1]
part1_reversed = part1[::-1]

decrypted_content2 = ''.join(chr((char) + 7) for char in part2_reversed)
decrypted_content1 = ''.join(chr((char) + 7) for char in part1_reversed)

print(decrypted_content2)
print(decrypted_content1)
