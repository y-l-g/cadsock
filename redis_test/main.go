package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

func main() {
	ctx := context.Background()
	channelName := "realtime:test"

	// 1. Se connecter à Redis
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// Vérifier que la connexion fonctionne
	if _, err := rdb.Ping(ctx).Result(); err != nil {
		log.Fatalf("Impossible de se connecter à Redis: %v", err)
	}
	fmt.Println("Connecté à Redis avec succès.")

	// 2. S'abonner au canal de test
	pubsub := rdb.Subscribe(ctx, channelName)
	// Attendre la confirmation de la souscription
	if _, err := pubsub.Receive(ctx); err != nil {
		log.Fatalf("Erreur lors de la confirmation de la souscription: %v", err)
	}
	fmt.Printf("Abonné avec succès au canal '%s'.\n", channelName)

	// 3. Lancer une goroutine pour écouter les messages
	// C'est la partie qui ne semble pas fonctionner dans notre projet
	go func() {
		ch := pubsub.Channel()
		fmt.Println("Goroutine d'écoute démarrée. En attente de messages...")
		for msg := range ch {
			// Si ce message s'affiche, c'est que l'écoute fonctionne !
			fmt.Printf("\n--- SUCCÈS ---\nMessage reçu: '%s' sur le canal '%s'\n-------------\n", msg.Payload, msg.Channel)
		}
	}()

	// 4. Attendre un court instant pour s'assurer que la goroutine est prête
	time.Sleep(1 * time.Second)

	// 5. Publier un message de test sur le même canal
	fmt.Println("Publication du message 'hello world'...")
	err := rdb.Publish(ctx, channelName, "hello world").Err()
	if err != nil {
		log.Fatalf("Erreur lors de la publication: %v", err)
	}

	// 6. Attendre encore pour laisser le temps à la goroutine de recevoir le message
	fmt.Println("Attente de 2 secondes pour voir le résultat...")
	time.Sleep(2 * time.Second)

	fmt.Println("Test terminé.")
}