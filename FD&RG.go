package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/IBM/sarama"            
	"github.com/go-redis/redis"        
	_ "github.com/go-sql-driver/mysql"
)

type ChatMessage struct {
	ID        string    `json:"id"`        
	SessionID string    `json:"sessionId"` 
	Timestamp time.Time `json:"timestamp"` 
	Sender    string    `json:"sender"`    
	Content   string    `json:"content"`   
}

type DetectionResponse struct {
	Scam  bool   `json:"scam"`  // 是否判定为诈骗
	Reply string `json:"reply"` // 模型生成的回复内容
}

var (
	db            *sql.DB
	redisClient   *redis.Client
	kafkaProducer sarama.SyncProducer
)

func main() {
	var err error
	db, err = sql.Open("mysql", "root:Fay0810_@tcp(localhost:3306)/chatdb?charset=utf8mb4&parseTime=True")
	if err != nil {
		log.Fatalf("MySQL连接失败: %v", err)
	}
	defer db.Close()

	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", 
	})
	if err := redisClient.Ping().Err(); err != nil {
		log.Fatalf("Redis连接失败: %v", err)
	}

	producerConfig := sarama.NewConfig()
	producerConfig.Producer.Return.Successes = true
	kafkaProducer, err = sarama.NewSyncProducer([]string{"localhost:9092"}, producerConfig)
	if err != nil {
		log.Fatalf("Kafka生产者初始化失败: %v", err)
	}
	defer kafkaProducer.Close()


	consumerGroup, err := sarama.NewConsumerGroup([]string{"localhost:9092"}, "chat_consumer_group", nil)
	if err != nil {
		log.Fatalf("Kafka消费者组初始化失败: %v", err)
	}
	defer consumerGroup.Close()

	consumer := Consumer{
		ready: make(chan bool),
	}

	ctx := context.Background()
	go func() {
		for {
			// 消费主题 "chat_messages"
			if err := consumerGroup.Consume(ctx, []string{"chat_messages"}, &consumer); err != nil {
				log.Printf("消费者出错: %v", err)
				time.Sleep(2 * time.Second)
			}
			// 若 context 被取消则退出
			if ctx.Err() != nil {
				return
			}
			consumer.ready = make(chan bool)
		}
	}()

	<-consumer.ready
	log.Println("Kafka消费者组已启动,开始反诈骗！")

	// 主进程阻塞
	select {}
}

type Consumer struct {
	ready chan bool
}

func (consumer *Consumer) Setup(sarama.ConsumerGroupSession) error {
	close(consumer.ready)
	return nil
}

func (consumer *Consumer) Cleanup(sarama.ConsumerGroupSession) error {
	return nil
}

func (consumer *Consumer) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		log.Printf("收到消息: partition=%d, offset=%d, value=%s", msg.Partition, msg.Offset, string(msg.Value))

		var chatMsg ChatMessage
		if err := json.Unmarshal(msg.Value, &chatMsg); err != nil {
			log.Printf("消息解析失败: %v", err)
			session.MarkMessage(msg, "")
			continue
		}

		if err := saveChatLog(chatMsg); err != nil {
			log.Printf("保存聊天记录失败: %v", err)
		}

		if err := appendConversation(chatMsg.SessionID, chatMsg); err != nil {
			log.Printf("保存会话历史失败: %v", err)
		} else {
			// 设置会话数据的过期时间7天
			key := fmt.Sprintf("session:%s:history", chatMsg.SessionID)
			redisClient.Expire(key, 7*24*time.Hour)
		}

		// 从 Redis 获取当前会话完整历史记录，传给模型服务做诈骗检测
		conversation, err := getConversation(chatMsg.SessionID)
		if err != nil {
			log.Printf("获取会话历史失败: %v", err)
			session.MarkMessage(msg, "")
			continue
		}

		// 生成回复内容
		isScam, reply, err := detectScam(conversation)
		if err != nil {
			log.Printf("调用模型接口失败: %v", err)
			session.MarkMessage(msg, "")
			continue
		}

		// 如果判断为诈骗，则发送系统回复并启动定时对话
		if isScam {
			log.Printf("警告！！！SOS诈骗警报！！！会话 %s 判定为诈骗，将接替原主人主动应答", chatMsg.SessionID)
			sysMsg := ChatMessage{
				ID:        fmt.Sprintf("sys-%d", time.Now().UnixNano()),
				SessionID: chatMsg.SessionID,
				Timestamp: time.Now(),
				Sender:    "system",
				Content:   reply,
			}

			if err := sendKafkaResponse(sysMsg); err != nil {
				log.Printf("发送系统回复失败: %v", err)
			}

			// 启动协程定时回复浪费诈骗者时间
			go engageScammer(chatMsg.SessionID)
		} else {
			log.Printf("会话 %s 判定为正常", chatMsg.SessionID)
		}

		session.MarkMessage(msg, "")
	}
	return nil
}

func detectScam(conversation []ChatMessage) (bool, string, error) {
	payload, err := json.Marshal(conversation)
	if err != nil {
		return false, "", err
	}
	// 调用模型服务接口（请确保模型服务已部署并正确配置地址）
	req, err := http.NewRequest("POST", "http://localhost:8084/scam-detect", nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(bytesReader(payload))

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	var detResp DetectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&detResp); err != nil {
		return false, "", err
	}
	return detResp.Scam, detResp.Reply, nil
}

// engageScammer 定时发送回复拖延诈骗者时间，示例中回复5次，每10秒一次
func engageScammer(sessionID string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	count := 0
	for range ticker.C {
		if count >= 5 {
			break
		}
		replyContent := fmt.Sprintf("系统自动回复：请问有什么问题吗？（%d）", count+1)
		responseMsg := ChatMessage{
			ID:        fmt.Sprintf("sys-%d", time.Now().UnixNano()),
			SessionID: sessionID,
			Timestamp: time.Now(),
			Sender:    "system",
			Content:   replyContent,
		}
		if err := sendKafkaResponse(responseMsg); err != nil {
			log.Printf("持续回复失败: %v", err)
		}
		count++
	}
}

func sendKafkaResponse(response ChatMessage) error {
	topic := "chat_responses"
	value, err := json.Marshal(response)
	if err != nil {
		return err
	}
	msg := &sarama.ProducerMessage{
		Topic: topic,
		Value: sarama.ByteEncoder(value),
	}
	partition, offset, err := kafkaProducer.SendMessage(msg)
	if err != nil {
		return err
	}
	log.Printf("系统回复已发送: topic=%s, partition=%d, offset=%d", topic, partition, offset)
	return nil
}


func saveChatLog(chat ChatMessage) error {
	query := "INSERT INTO chat_logs (id, session_id, sender, content, timestamp) VALUES (?, ?, ?, ?, ?)"
	_, err := db.Exec(query, chat.ID, chat.SessionID, chat.Sender, chat.Content, chat.Timestamp)
	return err
}


func appendConversation(sessionID string, chat ChatMessage) error {
	key := fmt.Sprintf("session:%s:history", sessionID)
	data, err := json.Marshal(chat)
	if err != nil {
		return err
	}
	return redisClient.RPush(key, data).Err()
}


func getConversation(sessionID string) ([]ChatMessage, error) {
	key := fmt.Sprintf("session:%s:history", sessionID)
	result, err := redisClient.LRange(key, 0, -1).Result()
	if err != nil {
		return nil, err
	}
	var conversation []ChatMessage
	for _, item := range result {
		var chat ChatMessage
		if err := json.Unmarshal([]byte(item), &chat); err != nil {
			continue
		}
		conversation = append(conversation, chat)
	}
	return conversation, nil
}


func bytesReader(b []byte) io.Reader {
	return &byteReader{data: b}
}

type byteReader struct {
	data []byte
	pos  int
}

func (br *byteReader) Read(p []byte) (n int, err error) {
	if br.pos >= len(br.data) {
		return 0, io.EOF
	}
	n = copy(p, br.data[br.pos:])
	br.pos += n
	return
}
