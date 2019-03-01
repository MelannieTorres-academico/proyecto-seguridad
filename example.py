#  https://docs.pytest.org/en/latest/example/simple.html
#  to run the tests use:
#  python3 -m pytest -q example.py or
#  python -m pytest -q example.py


#  Important: add documentation as indicated, one line for what does it do
#  all documentation and variables in english
#  One line with params, showing fist type and then its name
#  return type and name


from Crypto.Hash import SHA256
from time import time

# calculates the hash
# params string message
# returns the hexadecimal string
def _hash(string):
    hash = SHA256.new()
    hash.update(string.encode('utf-8'))
    result = hash.digest()
    return result


# Section will all tests (in this example I only added one, but you should add all)
def test_1_hash():
    #ciclo de 1000
    #start time
    start_time = time()
    for i in range(1000):
        _hash("message")
    #end time
    elapsed_time = (time() - start_time)/1000
    print("Elapsed time: %.10f seconds." % elapsed_time)


def main():
    test_1_hash()

if __name__ == "__main__":
    main()
