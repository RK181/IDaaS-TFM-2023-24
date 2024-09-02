package models

/*
var webClientID = ""

// var webID = 0
var netiveClientID = ""

//var nativeID = 0

func TestCreateNativeClient(t *testing.T) {
	userID := 1
	clientName := "TestNativeClient"
	secret := "testSecret"
	redirectURIs := []string{"http://localhost/auth/callback"}

	client, err := CreateNativeClient(userID, clientName, secret, redirectURIs)
	if err != nil {
		t.Errorf("Error creating native client: %v", err)
	}

	// Assert client properties
	if client.GetID() == "" {
		t.Error("Client ID should not be empty")
	}
	if client.RedirectURIs() == nil {
		t.Error("Redirect URIs should not be nil")
	}
	if client.ApplicationType() != op.ApplicationTypeNative {
		t.Error("Application type should be Native")
	}

	netiveClientID = client.GetID()
}
func TestCreateWebClient(t *testing.T) {
	userID := 1
	clientName := "TestWebClient"
	secret := "testSecret"
	redirectURIs := []string{"http://localhost:9999/auth/callback"}

	client, err := CreateWebClient(userID, clientName, secret, redirectURIs)
	if err != nil {
		t.Errorf("Error creating web client: %v", err)
	}

	// Assert client properties
	if client.GetID() == "" {
		t.Error("Client ID should not be empty")
	}
	if client.RedirectURIs() == nil {
		t.Error("Redirect URIs should not be nil")
	}
	if client.ApplicationType() != op.ApplicationTypeWeb {
		t.Error("Application type should be Web")
	}
	webClientID = client.GetID()
}
func TestGetClientByClientID(t *testing.T) {
	clientID := netiveClientID

	client, err := GetClientByClientID(clientID)
	if err != nil {
		t.Errorf("Error getting client by ID: %v", err)
	}

	// Assert client properties
	if client.GetID() != clientID {
		t.Errorf("Expected client ID: %s, got: %s", clientID, client.GetID())
	}
	if client.RedirectURIs() == nil {
		t.Error("Redirect URIs should not be nil")
	}

}

func TestGetClientsByUserID(t *testing.T) {
	userID := 1

	clients, err := GetClientsByUserID(userID)
	if err != nil {
		t.Errorf("Error getting clients by user ID: %v", err)
	}

	// Assert number of clients
	expectedCount := 2
	if len(clients) != expectedCount {
		t.Errorf("Expected %d clients, got %d", expectedCount, len(clients))
	}

	// Assert client properties
	for _, client := range clients {
		if client.GetID() == "" {
			t.Error("Client ID should not be empty")
		}
		if client.RedirectURIs() == nil {
			t.Error("Redirect URIs should not be nil")
		}
		if client.ApplicationType() != op.ApplicationTypeWeb && client.ApplicationType() != op.ApplicationTypeNative {
			t.Error("Application type should be Web or Native")
		}
	}
}

func TestDeleteClient(t *testing.T) {
	client := &Client{
		clientID: netiveClientID,
	}
	err := DeleteClient(client)
	if err != nil {
		t.Errorf("Error deleting client: %v", err)
	}

	client = &Client{
		clientID: webClientID,
	}
	err = DeleteClient(client)
	if err != nil {
		t.Errorf("Error deleting client: %v", err)
	}
}
*/
