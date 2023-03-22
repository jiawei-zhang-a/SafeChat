# SafeChat

SafeChat is a secure messaging application that uses the Signal protocol to provide end-to-end encryption for messages exchanged between users. The application is built using the Go programming language and uses a crypto library that includes AES-GCM, SHA-256, and P-256 algorithms.

## Getting Started

To get started with SafeChat, you will need to have Go installed on your machine. You can download and install the latest version of Go from the [official website](https://golang.org/dl/).

Once you have Go installed, you can clone the SafeChat repository from GitHub:

``` git clone https://github.com/yourusername/safechat.git ```


After cloning the repository, navigate to the project directory:

```cd safechat```

Then, you can run the application using the following command:

```go run main.go```


This will start the SafeChat application, and you will be prompted to enter your username and password to log in.

## Features

SafeChat provides the following features:

- Secure end-to-end encryption for messages using the Signal protocol
- User authentication using a username and password
- Ability to send and receive messages between users
- Ability to create and join chat rooms with other users
- Ability to send and receive files

## Dependencies

SafeChat uses the following libraries and frameworks:

- Go 1.16
- [Signal Go](https://github.com/bbernhard/signal-go) - an implementation of the Signal protocol in Go
- [GORM](https://gorm.io/) - a Go ORM library for database management
- [Gorilla WebSockets](https://github.com/gorilla/websocket) - a Go library for building WebSocket applications

## Security

SafeChat is designed with security in mind and uses the Signal protocol to provide end-to-end encryption for messages. The crypto library used by the application includes the AES-GCM, SHA-256, and P-256 algorithms, which are considered secure and widely used in the industry.

However, please note that no software can guarantee absolute security, and SafeChat should be used at your own risk.

## Contributing

If you would like to contribute to SafeChat, please submit a pull request with your changes. Before submitting a pull request, please ensure that your code follows the Go code style guidelines and that all tests pass.

## License

SafeChat is licensed under the [GNU License](LICENSE).
