# Doa Forum Server

Doa is a simple forum server that allows users to register and authenticate to join a forum. It provides basic security features like password policies, encryption, and hashing to ensure that user data is protected.

## Basic Requirements

The Doa Forum Server meets the following basic requirements:

- Allows clients to register with a unique username and password.
- Clients can authenticate themselves to the server and join the forum.
- Registration and authentication messages are sent through a non-GUI function call.

## Advanced Requirements

In addition to the basic requirements, the Doa Forum Server also offers the following advanced features:

- Communication between client and server is encrypted to ensure data privacy.
- A graphical user interface is available to support user registration and authentication.
- Password policies can be set by the server to ensure password strength.

## Getting Started

To get started with the Doa Forum Server, follow these steps:

1. Clone the Doa Forum Server repository from GitHub.
2. Build the project using your preferred Java IDE or build tool.
3. Start the server by running the Server.main() method.
4. Connect to the server using the provided client or by sending messages through a non-GUI function call.

## Usage

To use the Doa Forum Server, you can either use the provided client or write your own implementation using the non-GUI function calls. Here are some examples of how to use the server:

### Registering a User

To register a new user, call the `register(String username, String password)` method, passing in the desired username and password as parameters. If the registration is successful, the method will return a string "Registration successful". If the username is already taken, the method will return a string "Username already exists". If the password does not meet the server's password policies, the method will throw an exception with the message "Password does not meet policy requirements".

### Authenticating a User

To authenticate a user, call the `authenticate(String username, String password)` method, passing in the user's username and password as parameters. If the authentication is successful, the method will return a string "You are authenticated, Welcome ". If the username or password is incorrect, the method will throw an exception with the message "Please enter correct username password".

## License

The Doa Forum Server is licensed under the MIT License. See the LICENSE file for details.

