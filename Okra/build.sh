set -x
set -e

BUILD_TYPE=$1

if [ ${BUILD_TYPE} ==  "verify" ];
then
  cd wrapper/sgx/
  make clean
  make verify
  cd -

  cd wrapper/phytium/
  make verify
  cd -
fi

if [ ${BUILD_TYPE} ==  "sgx" ];
then
  cd wrapper/sgx/
  make clean
  make
  cd -
fi

if [ ${BUILD_TYPE} ==  "phytium" ];
then
  cd wrapper/phytium/
  make
  cd -
fi

echo "Compile proto file for attestation center."
cd attestation_center
python3 -m grpc_tools.protoc --proto_path=../proto/ ../proto/hetero_attestation.proto --python_out=./ --grpc_python_out=./
cd -

echo "Compile proto file for tee node."
cd tee_node
python3 -m grpc_tools.protoc --proto_path=../proto/ ../proto/hetero_attestation.proto --python_out=./ --grpc_python_out=./
