### Conceptual Exercise

Answer the following questions below:

- What is a JWT?
JWT is JSON Web Token. JWTs are an open standard and are implemented across technology stacks, making it simple to share tokens across different services

JWTs can store any arbitary 'payload' of info, which are 'signed' using a secret key, so they can be validated later

- What is the signature portion of the JWT?  What does it do?

version of header & payload, signed with secret key

- If a JWT is intercepted, can the attacker see what's inside the payload?

they can decode and view the contents of the payload. 
JWTs are encoded using base64, not encrypted.

- How can you implement authentication with a JWT?  Describe how it works at a high level.

User creates a secret_key and payload
let token = jwt.sign(payload, secret_key)
jwt.verify(token, secret_key)


- Compare and contrast unit, integration and end-to-end tests.

Unit: Individual units or components, verify behavior of individual units, mocked or stubbed external dependencies

Integration: interactions between multiple units/components, Ensure integration and collaboration, Real or simulated external dependencies

End-to-end: Entire software system, validate user workflows and system behvaior, Real extrnal dependencies.

- What is a mock? What are some things you would mock?

- What is continuous integration?

- What is an environment variable and what are they used for?

- What is TDD? What are some benefits and drawbacks?

- What is the value of using JSONSchema for validation?

- What are some ways to decide which code to test?

- What does `RETURNING` do in SQL? When would you use it?

- What are some differences between Web Sockets and HTTP?

- Did you prefer using Flask over Express? Why or why not (there is no right
  answer here --- we want to see how you think about technology)?
