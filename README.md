# Test HTTP server made for the course on Boot.dev

This server is designed to handle the posting and retrieval of "chirps"; a fake version of a tweet 

## Requirements and setup

This server was built using **GO** 1.24 and **PostrgreSQL** 15.12

After setting up your SQL database find your connection string and create a .env file in the servers directory. Assign your connection string such that it looks like this
"DB_URL="yourconnectionstring". Here you will also set your "secret" and "POLKA_KEY" similarly. The secret can be any arbitrary string but i recommend using something to generate one.
The POLKA_KEY is similar in that it can be just about anything, just make sure anything thats making secure requests to the server also has this key. After all this is setup you
can run "go build ." to create an exe that will run the server when executed. As a side note make sure all requests default to "Localhost:####/app/" 

## Usage

The server current supports 12 different endpoints;

 - Get /api/healthz: A simple test endpoint to ensure the server is actually running
 - Get /admin/metrics: Serves a page that shows how many times Chirpy has been visited
 - POST /admin/reset: Resets the database, clearing all users and chirps; IS NOT REVERSIBLE
 - POST /api/chirps: This endpoint, all in one request, will verify if the chirp is in the character limit, verify that the user is the currently logged in user, and add the chirp to the database
 - POST /api/users: Will create a user in the database. Request requires both a user name and a password. Stores a hashed version of the password and returns the username and an empty password if it worked correctly.
 - GET /api/chirps: Returns all chirps found in the database. Optionally takes a user id to get all the chirps made by that user, aswell as an optional sort query that lets you sort by descending date(default is ascending)
 - GET /api/chirps/(chirpID): Returns the chirp with the given id
 - POST /api/login: Sets the current user aswell as verifies the credential in the http request
 - POST /api/refresh: Issues a new JWT token for the current user thats used for authentification
 - POST /api/revoke: revokes the users token
 - PUT /api/users: Updates the users login information
 - DELETE /api/chirps/(chirpID): Deletes the chirp at the given id
 - POST /api/polka/webhooks: a webhook that sets the users entry in the database as a ChirpyRed user.

