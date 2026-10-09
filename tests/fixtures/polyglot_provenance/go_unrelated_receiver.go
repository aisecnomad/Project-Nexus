package main

import "github.com/tmc/langchaingo/llms"

type Queue struct{}

func (q Queue) NewExecutor() {}

func run() {
    _ = llms.MessageContent{}
    agents := Queue{}
    agents.NewExecutor()
}
