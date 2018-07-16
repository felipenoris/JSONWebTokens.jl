
import hmac
import hashlib
import base64

def base64url_decode(input):
    if isinstance(input, text_type):
        input = input.encode('ascii')

    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')

header = b'{"alg":"HS256","typ":"JWT"}'
payload = b'{"sub":"1234567890","name":"John Doe","iat":1516239022}'
secret = b'123'

header_and_payload = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'

dig = hmac.new(secret, msg=header_and_payload, digestmod=hashlib.sha256).digest()
print(base64url_encode(dig) == b'pF3q46_CLIyP_1QZPpeccbs-hC4n9YW2VMBjKrSO6Wg')
