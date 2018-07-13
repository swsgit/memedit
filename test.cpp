#include <iostream>

using namespace std;

struct Player {
    int level;
    int hp;
};

struct Game {
    Player *player;
};

Game *game;
int main() {
    game= new Game;
    game->player = new Player;
    game->player->level = 1;
    game->player->hp = 100;

    while (1) {
        cout << "player hp: " << game->player->hp;
        cin.get();
        game->player->hp--;
    }

    return 0;
}