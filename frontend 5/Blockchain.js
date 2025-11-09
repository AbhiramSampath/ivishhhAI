import React, { useState } from 'react';
import { View, Text, StyleSheet, SafeAreaView, TouchableOpacity, TextInput, Alert, Clipboard } from 'react-native';
import { Svg, Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native'; // <-- Import the hook
import { regenerateDID, exportPrivateKey } from './api/index';

const QRCode = () => <Text>QRCode Component (Placeholder)</Text>; // Dummy component to prevent errors

// The SVG back icon component, defined within this file.
const NavIconsBack = () => (
  <View style={styles.navIconsBackContainer}>
    <Svg width="8" height="14" viewBox="0 0 8 14" fill="none">
      <Path d="M7 1L1 7L7 13" stroke="#2C2C2C" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  </View>
);

const BlockchainScreen = () => {
  const navigation = useNavigation(); // <-- Initialize the hook
  const [didIdValue, setDidIdValue] = useState('1234567890@12345');

  const onCopyPress = () => {
    Clipboard.setString(didIdValue);
    Alert.alert('Copied', 'DID copied to clipboard');
  };

  const onExportPrivateKey = () => {
    Alert.prompt(
      'Enter Encryption Password',
      'Enter a password to encrypt the private key',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'OK', onPress: async (password) => {
          if (!password) {
            Alert.alert('Error', 'Password is required');
            return;
          }
          try {
            const data = await exportPrivateKey('dummy_user_token_1234567890', password);
            Alert.alert('Success', `Encrypted Private Key: ${data.encrypted_private_key}`);
          } catch (error) {
            Alert.alert('Error', 'Failed to export private key');
          }
        }},
      ],
      'secure-text'
    );
  };

  const onRegenerateId = async () => {
    try {
      const data = await regenerateDID('dummy_user_token_1234567890');
      setDidIdValue(data.did);
      Alert.alert('Success', 'DID regenerated');
    } catch (error) {
      Alert.alert('Error', 'Failed to regenerate DID');
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <NavIconsBack />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Blockchain Identity</Text>
      </View>

      {/* DID ID Section */}
      <View style={styles.didIdSection}>
        <View style={styles.didIdInfo}>
          <View style={styles.didIcon} />
          <View>
            <Text style={styles.didIdLabel}>DID ID</Text>
            <Text style={styles.didIdValue}>{didIdValue}</Text>
          </View>
        </View>
        <TouchableOpacity onPress={onCopyPress} style={styles.copyButton}>
          <Text style={styles.copyButtonText}>Copy</Text>
        </TouchableOpacity>
      </View>

      {/* QR Code Section */}
      <View style={styles.qrSection}>
        <View style={styles.qrCodeContainer}>
          <QRCode
            value={didIdValue}
            size={200}
            backgroundColor="#F0F0F0"
            color="black"
          />
        </View>
        <Text style={styles.qrDescription}>
          This digital ID is generated just for you. It's your secure identifier for decentralized platforms and apps
        </Text>
      </View>

      {/* Button Group */}
      <View style={styles.buttonGroup}>
        <TouchableOpacity onPress={onExportPrivateKey} style={styles.primaryButton}>
          <Text style={styles.primaryButtonText}>Export Private Key</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={onRegenerateId} style={styles.secondaryButton}>
          <Text style={styles.secondaryButtonText}>Regenerate ID</Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF', // Changed to white
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 20,
    paddingTop: 44, // Changed from 30
    paddingBottom: 4,
    paddingHorizontal: 20, // Changed from paddingLeft: 12
    columnGap: 8, // Using gap for better spacing
    
  },
  headerTitle: {
    color: '#0C0D11',
    fontSize: 20,
    fontWeight: '500', // Changed from bold
    marginRight:5,
  },
  navIconsBackContainer: {
    position: "relative",
    flexShrink: 0,
    height: 36,
    width: 36,
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-start",
    rowGap: 0,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight:5,
  },
  didIdSection: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#FFFFFF', // Changed to white
    borderRadius: 10,
    padding: 15,
    marginBottom: 30,
    marginHorizontal: 20,
  },
  didIdInfo: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  didIcon: {
    width: 40,
    height: 40,
    backgroundColor: '#2C2C2C',
    borderRadius: 5,
    marginRight: 10,
  },
  didIdLabel: {
    color: '#848484',
    fontSize: 12,
  },
  didIdValue: {
    color: '#0C0D11',
    fontSize: 16,
    fontWeight: 'bold',
  },
  copyButton: {
    backgroundColor: '#FFFFFF', // Changed to white
    paddingVertical: 8,
    paddingHorizontal: 15,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: '#848484'
  },
  copyButtonText: {
    color: '#2C2C2C',
    fontWeight: 'bold',
  },
  qrSection: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 20,
  },
  qrCodeContainer: {
    backgroundColor: '#F0F0F0', // Changed to a subtle gray for contrast
    padding: 20,
    borderRadius: 15,
    shadowColor: '#0C0D11',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 3.84,
    elevation: 5,
  },
  qrDescription: {
    color: '#2C2C2C',
    textAlign: 'center',
    marginTop: 20,
    fontSize: 14,
    lineHeight: 20,
    paddingHorizontal: 20,
  },
  buttonGroup: {
    marginTop: 20,
    paddingHorizontal: 20,
    marginBottom: 20,
  },
  primaryButton: {
    height: 52,
    backgroundColor: '#0C0D11',
    alignSelf: 'stretch',
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 32,
    paddingVertical: 14,
    borderRadius: 12,
    marginBottom: 15,
  },
  primaryButtonText: {
    textAlign: 'center',
    color: '#F6F6F8',
    fontSize: 17,
    fontWeight: '700',
  },
  secondaryButton: {
    height: 52,
    backgroundColor: '#E0E0E0',
    alignSelf: 'stretch',
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 32,
    paddingVertical: 14,
    borderRadius: 12,
  },
  secondaryButtonText: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#2C2C2C',
  },
});

export default BlockchainScreen;
