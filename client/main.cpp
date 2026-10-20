#include <iostream>

#include "Constants.h"

int main()
{
    std::cout << "File transfer client, version " << static_cast<int>(constants::CLIENT_VERSION) << std::endl;
    return 0;
}
