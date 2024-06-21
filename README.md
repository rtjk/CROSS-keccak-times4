# CROSS-keccak-times4

Test setup:
* CPU: `Intel(R) Core(TM) i7-6500U CPU @ 2.50GHz`
* Battery: plugged in, not charging

Run speed test:
* Build:
    ```
    cd Additional_Implementations/test_speed/
    rm -rf build
    mkdir build
    cd build
    cmake ../
    make
    cd ..
    ```
* Set CPU frqeuency to min until the next reboot:
    ```
    sudo cpufreq-set -c 0 --min 400000 --max 400000
    sudo cpufreq-set -c 1 --min 400000 --max 400000
    sudo cpufreq-set -c 2 --min 400000 --max 400000
    sudo cpufreq-set -c 3 --min 400000 --max 400000
    ```
* Collect results:
    ```
    cd build/bin
    for file in *; do if [[ -x "$file" && ! -d "$file" ]]; then echo "$file"; ./"$file"; fi; done
    ```
