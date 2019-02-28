#  https://docs.pytest.org/en/latest/example/simple.html
#  to run the tests use:
#  python3 -m pytest -q example.py or
#  python -m pytest -q example.py


#  Important: add documentation as indicated, one line for what does it do
#  all documentation and variables in english
#  One line with params, showing fist type and then its name
#  return type and name


from Crypto.Hash import SHA256

# Gets the hexadecimal given an array of bytes
# params: array A
# return: hexadecimal string
def toHex(A):
    newA = []
    for i in range(len(A)):
        newA.append('{:02x}'.format(A[i]))
    return ''.join(newA).upper()

# calculates the hash
# params string message
# returns the hexadecimal string
def _hash(string):
    hash = SHA256.new()
    hash.update(string.encode('utf-8'))
    result = hash.digest()
    return toHex(result)


# Section will all tests (in this example I only added one, but you should add all)
def test_1_hash():
    assert _hash('') == 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'



def main():
    result = _hash("message")
    print(toHex(result))

if __name__ == "__main__":
    main()
