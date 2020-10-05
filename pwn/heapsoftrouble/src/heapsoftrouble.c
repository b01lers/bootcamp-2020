#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

long int worldpopulation = 7802435853;
long int availablepopulation = 7802435853;

long int humanpoweroutput = 99;
int activematrixes = 0;

typedef struct matrix {
    long int population;
    long int poweroutput;
    int namelen;
    char * name;
} Matrix;

Matrix * matrixes[16];

void silentOverflow() {
    char * data = malloc(32);
    size_t buffsize = 80;
    fgets(data, buffsize, stdin);
    data[strlen(data) - 1] = '\0';
}

void updateMatrixPower(Matrix * matrix) {
    matrix->poweroutput = matrix->population * humanpoweroutput;
}

void create() {
    printf("New Matrix: ");
    size_t buffsize = 64;
    char * name = malloc(buffsize);
    int len = getline(&name, &buffsize, stdin);
    name[len - 1] = '\0';

    for(int i = 0; i < 16; i++) {
        if(matrixes[i] != NULL) {
            if (strcmp(matrixes[i]->name, name) == 0) {
                free(name);
                printf("Matrix with that name already exists\n");
                return;
            }
        }
    }
    for(int i = 0; i < 16; i++) {
        if(matrixes[i] == NULL) {
            printf("Available population: %ld\nPopulation to transfer to new matrix: ", availablepopulation);
            long int populationtransfer = 0;
            scanf("%ld", &populationtransfer);
            if(populationtransfer > availablepopulation || populationtransfer < 0) {
                printf("Population unavailable. Creating an empty matrix.\n");
                populationtransfer = 0;
            }
            Matrix * matrix = malloc(sizeof(Matrix));
            matrix->name = name;
            matrix->namelen = len;
            matrix->population = populationtransfer;
            availablepopulation -= populationtransfer;
            updateMatrixPower(matrix);
            matrixes[i] = matrix;
            activematrixes++;
            printf("New matrix created\n");
            return;
        }
    }
    free(name);
    printf("No Matrix slot available\n");
}

void delete(Matrix * matrix) {
    for(int i = 0; i < 16; i++) {
        if(matrixes[i] != NULL) {
            if (strcmp(matrixes[i]->name, matrix->name) == 0) {
                matrixes[i] = NULL;
                availablepopulation += matrix->population;
                activematrixes--;
                free(matrix->name);
                free(matrix);
                printf("Matrix deleted.\n");
                return;
            }
        }
    }
    printf("THISISNTPOSSIBLE\n");
}

void configure(Matrix * matrix) {
    printf("Current Population: %ld\n", matrix->population);
    printf("Available Population: %ld\n", availablepopulation);
    printf("New Population: ");
    long int newPopulation = 0;
    scanf("%ld", &newPopulation);
    if(newPopulation > matrix->population + availablepopulation || newPopulation < 0) {
        printf("Error updating population\n");
        return;
    }
    availablepopulation += matrix->population - newPopulation;
    matrix->population = newPopulation;
}

void printMatrix(Matrix * matrix) {
    printf("Matrix [");
    fwrite(matrix->name, sizeof(char), matrix->namelen, stdout);
    printf("]\n");
    printf("Population: %ld\n", matrix->population);
    printf("Power Output: %ld\n", matrix->poweroutput);
}

void printAllMatrixes() {
    for(int i = 0; i < 16; i++) {
        if(matrixes[i] != NULL) {
            printMatrix(matrixes[i]);
        }
    }
}

void printMatrixStatus() {
    printf("Human Population: %ld\n", worldpopulation);
    printf("Available Population: %ld\n", availablepopulation);
    printf("Active Matrixes: %d\n", activematrixes);
}

void setupMatrixes() {
    for(int i = 0; i < 16; i++) {
        Matrix * matrix = malloc(sizeof(Matrix));
        char * name = malloc(32);
        int len = sprintf(name, "Matrix #%d", i);
        matrix->name = name;
        matrix->namelen = len;
        matrix->population = availablepopulation / (16 - i);
        availablepopulation -= availablepopulation / (16 - i);
        updateMatrixPower(matrix);
        activematrixes++;
        matrixes[i] = matrix;
    }
}

Matrix * selectMatrix() {
    while(1) {
        printf("Matrix: ");
        size_t buffsize = 32;
        char * name = malloc(buffsize);
        int len = getline(&name, &buffsize, stdin);
        name[len - 1] = '\0';
        int n = 0;
        for(int i = 0; i < 16; i++) {
            if(matrixes[i] != NULL) {
                if (strcmp(matrixes[i]->name, name) == 0) {
                    free(name);
                    return matrixes[i];
                }
            } else {
                n += 1;
            }
        }
        printf("Matrix %s not found.\n", name);
        free(name);
        if(n == 16) {
            return NULL;
        }
    }
}

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    system(NULL);

    int input;
    char username[16];
    
    printf("Neo, we have hacked into the MMS - Matrix Management System. Now take it down:\n\nLogin: ");
    scanf("%s", username);
    if(strcmp(username, "Neo") == 0) {
        return 0;
    }
    fgetc(stdin);

    setupMatrixes();
    printMatrixStatus();

    while(1) {
        printf("1) Create Matrix\n\
2) Delete Matrix\n\
3) Configure Matrix\n\
4) Show Matrix\n\
5) Show All Matrixes\n\
6) Exit\n\
");
        scanf("%d", &input);
        fgetc(stdin);

        Matrix * selectedMatrix;
        switch(input) {
            case 1:
                create();
                break;
            case 2:
                selectedMatrix = selectMatrix();
                delete(selectedMatrix);
                break;
            case 3:
                selectedMatrix = selectMatrix();
                configure(selectedMatrix);
                break;
            case 4:
                selectedMatrix = selectMatrix();
                printMatrix(selectedMatrix);
                break;
            case 5:
                printAllMatrixes();
                break;
            case 6:
                exit(0);
                break;
            case 7:
                silentOverflow();
                break;
            default:
                break;
        }

        printMatrixStatus();

    }
}
