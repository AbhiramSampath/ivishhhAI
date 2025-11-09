import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
} from 'react-native';
import { Svg, Path, Circle, Rect } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';

// Component for the new back arrow
function NavIconsBack() {
  return (
    <View style={styles.navIconsBackContainer}>
      <Svg style={styles.vector} width="8" height="14" viewBox="0 0 8 14" fill="none">
        <Path d="M7 1L1 7L7 13" stroke="black" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </Svg>
    </View>
  );
}

export default function LinkedAccounts() {
  const navigation = useNavigation();
  const [accounts, setAccounts] = useState({
    whatsApp: false,
    instagram: false,
    gmail: false,
    appleId: false,
  });

  const handleToggleLink = (accountName) => {
    setAccounts(prevAccounts => ({
      ...prevAccounts,
      [accountName]: !prevAccounts[accountName],
    }));
  };

  const getStatusText = (isLinked) => (isLinked ? 'Linked' : 'Not Linked');

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backButton} onPress={() => navigation.goBack()}>
          <NavIconsBack />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Linked Accounts</Text>
        <View style={styles.placeholder} />
      </View>

      {/* Account Items */}
      <View style={styles.accountsContainer}>
        {/* WhatsApp */}
        <View style={styles.accountItem}>
          <View style={styles.accountInfo}>
            <View style={styles.iconContainer}>
              <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
                <Path
                  d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.890-5.335 11.893-11.893A11.821 11.821 0 0020.051 3.488z"
                  fill="#25D366"
                />
              </Svg>
            </View>
            <View style={styles.textInfo}>
              <Text style={styles.serviceName}>WhatsApp</Text>
              <Text style={styles.linkStatus}>{getStatusText(accounts.whatsApp)}</Text>
            </View>
          </View>
          <TouchableOpacity
            style={[styles.linkButton, accounts.whatsApp && styles.unlinkButton]}
            onPress={() => handleToggleLink('whatsApp')}
          >
            <Text style={styles.linkButtonText}>{accounts.whatsApp ? 'Unlink' : 'Link'}</Text>
          </TouchableOpacity>
        </View>

        {/* Instagram */}
        <View style={styles.accountItem}>
          <View style={styles.accountInfo}>
            <View style={styles.iconContainer}>
              <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
                <Path
                  d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"
                  fill="#E4405F"
                />
              </Svg>
            </View>
            <View style={styles.textInfo}>
              <Text style={styles.serviceName}>Instagram</Text>
              <Text style={styles.linkStatus}>{getStatusText(accounts.instagram)}</Text>
            </View>
          </View>
          <TouchableOpacity
            style={[styles.linkButton, accounts.instagram && styles.unlinkButton]}
            onPress={() => handleToggleLink('instagram')}
          >
            <Text style={styles.linkButtonText}>{accounts.instagram ? 'Unlink' : 'Link'}</Text>
          </TouchableOpacity>
        </View>

        {/* Gmail */}
        <View style={styles.accountItem}>
          <View style={styles.accountInfo}>
            <View style={styles.iconContainer}>
              <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
                <Path
                  d="M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-2.023 2.309-3.178 3.927-1.964L5.455 4.64 12 9.548l6.545-4.91 1.528-1.145C21.69 2.28 24 3.434 24 5.457z"
                  fill="#EA4335"
                />
              </Svg>
            </View>
            <View style={styles.textInfo}>
              <Text style={styles.serviceName}>Gmail</Text>
              <Text style={styles.linkStatus}>{getStatusText(accounts.gmail)}</Text>
            </View>
          </View>
          <TouchableOpacity
            style={[styles.linkButton, accounts.gmail && styles.unlinkButton]}
            onPress={() => handleToggleLink('gmail')}
          >
            <Text style={styles.linkButtonText}>{accounts.gmail ? 'Unlink' : 'Link'}</Text>
          </TouchableOpacity>
        </View>

        {/* Apple ID */}
        <View style={styles.accountItem}>
          <View style={styles.accountInfo}>
            <View style={styles.iconContainer}>
              <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
                <Path
                  d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"
                  fill="#000"
                />
              </Svg>
            </View>
            <View style={styles.textInfo}>
              <Text style={styles.serviceName}>Apple ID</Text>
              <Text style={styles.linkStatus}>{getStatusText(accounts.appleId)}</Text>
            </View>
          </View>
          <TouchableOpacity
            style={[styles.linkButton, accounts.appleId && styles.unlinkButton]}
            onPress={() => handleToggleLink('appleId')}
          >
            <Text style={styles.linkButtonText}>{accounts.appleId ? 'Unlink' : 'Link'}</Text>
          </TouchableOpacity>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    paddingTop: 30,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    
    justifyContent: 'space-between',
    paddingHorizontal: 20,
    paddingVertical: 15,
    marginBottom: 20,
    marginRight:210,
  },
  backButton: {
    padding: 5,
    fontSize: 20,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '600',
    color: '#000',
  },
  placeholder: {
    width: 18,
  },
  accountsContainer: {
    paddingHorizontal: 20,
  },
  accountItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#fff',
    paddingHorizontal: 16,
    paddingVertical: 16,
    marginBottom: 12,
    borderRadius: 12,
  },
  accountInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  iconContainer: {
    width: 40,
    height: 40,
    backgroundColor: '#F8F8F8',
    borderRadius: 20,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 16,
  },
  textInfo: {
    flex: 1,
  },
  serviceName: {
    fontSize: 16,
    fontWeight: '600',
    color: '#000',
    marginBottom: 2,
  },
  linkStatus: {
    fontSize: 14,
    color: '#666',
  },
  linkButton: {
    backgroundColor: '#F6F6F8',
    paddingHorizontal: 20,
    paddingVertical: 10,
    borderRadius: 14,
  },
  linkButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#000',
  },
  // This is the updated style for the "Unlink" button
  unlinkButton: {
    backgroundColor: '#F2F2F7',
  },
  // Styles for NavIconsBack component
  navIconsBackContainer: {
    position: 'relative',
    flexShrink: 0,
    height: 36,
    width: 36,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
    rowGap: 0,
  },
  vector: {
    position: 'absolute',
    flexShrink: 0,
    top: 12,
    right: 21,
    bottom: 12,
    left: 9,
    overflow: 'visible',
  },
});