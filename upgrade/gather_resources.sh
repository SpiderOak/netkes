cd $HOME/netkes/upgrade

rm -rf resources
mkdir resources

cd resources

pip install --download=. pip==1.4.1
pip install --download=. Django==1.5.5
