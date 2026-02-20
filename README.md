Yet another language that tries to be the modern c equivalent

```c++
enum EntityType {
    Player,
    Enemy,
    Projectile
}

struct Entity {
    type: EntityType,
    x: f32,
    y: f32,
    health: i32,
    active: bool
}

proc update_entity(e: Entity*) -> void {
    match e->type {
        EntityType:Player {
            // player logic
        },
        EntityType:Enemy {
            e->x += 1.0;
        },
        EntityType:Projectile {
            e->y -= 5.0;
            if e->y < 0.0 {
                e->active = false;
            }
        }
    }
}

proc print_entity(e: Entity*) -> void {
    match e->type {
        EntityType:Player     { printf("Player"); },
        EntityType:Enemy      { printf("Enemy"); },
        EntityType:Projectile { printf("Projectile"); }
    }
    printf(" at (%.1f, %.1f) hp=%d\n", e->x, e->y, e->health);
}

pub proc main() -> i32 {
    entities: Entity[3] = [
        Entity { EntityType:Player,      0.0, 0.0,  100, true },
        Entity { EntityType:Enemy,      10.0, 5.0,   30, true },
        Entity { EntityType:Projectile,  2.0, 8.0,    1, true }
    ];

    running: bool = true;
    while running {
        for i: i32 = 0; i < 3; i += 1 {
            e: Entity* = &entities[i];
            if e->active {
                update_entity(e);
                print_entity(e);
            }
        }
    }
    return 0;
}
```


