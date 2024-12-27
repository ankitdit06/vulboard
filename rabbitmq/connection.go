package rabbitmq

import (
	"fmt"

	"github.com/streadway/amqp"
)

func ConnectRabbitMQ(url string) (*amqp.Connection, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}
	return conn, nil
}
