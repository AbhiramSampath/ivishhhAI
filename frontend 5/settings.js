import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  Platform,
} from 'react-native';
import Svg, { Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';

// Standard Back Button Component
function NavIconsBack() {
  return (
    <View style={styles.navIconsBackContainer}>
      <Svg style={styles.vector} width="8" height="14" viewBox="0 0 8 14" fill="none">
        <Path
          d="M7 1L1 7L7 13"
          stroke="#2C2C2C" // Corrected stroke color to match established standard
          strokeWidth="1.7"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </Svg>
    </View>
  );
}

// Settings Menu Item Component
const SettingsMenuItem = ({ icon, label, onPress }) => (
  <TouchableOpacity
    style={styles.menuItem}
    onPress={onPress}
    activeOpacity={0.7}
  >
    <View style={styles.menuItemLeft}>
      {icon}
      <Text style={styles.menuItemLabel}>{label}</Text>
    </View>
    <Svg width="8" height="14" viewBox="0 0 8 14" fill="none">
      <Path
        d="M1 13L7 7L1 1"
        stroke="black"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </Svg>
  </TouchableOpacity>
);

export default function Settings() {
  const navigation = useNavigation();

  const handleMenuPress = screenName => {
    navigation.navigate(screenName);
  };

  return (
    <View style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* Header */}
        <View style={styles.header}>
          {/* Back button navigates to the previous screen */}
          <TouchableOpacity onPress={() => navigation.goBack()}>
            <NavIconsBack />
          </TouchableOpacity>
          <Text style={styles.headerTitle}>Settings</Text>
        </View>

        {/* Menu Items */}
        <View style={styles.menuContainer}>
          <SettingsMenuItem
            icon={
              <Svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                <Path
                  d="M6.16797 18.849C6.41548 18.0252 6.92194 17.3032 7.61222 16.79C8.30249 16.2768 9.13982 15.9997 9.99997 16H14C14.8612 15.9997 15.6996 16.2774 16.3904 16.7918C17.0811 17.3062 17.5874 18.0298 17.834 18.855M3 12C3 13.1819 3.23279 14.3522 3.68508 15.4442C4.13738 16.5361 4.80031 17.5282 5.63604 18.364C6.47177 19.1997 7.46392 19.8626 8.55585 20.3149C9.64778 20.7672 10.8181 21 12 21C13.1819 21 14.3522 20.7672 15.4442 20.3149C16.5361 19.8626 17.5282 19.1997 18.364 18.364C19.1997 17.5282 19.8626 16.5361 20.3149 15.4442C20.7672 14.3522 21 13.1819 21 12C21 10.8181 20.7672 9.64778 20.3149 8.55585C19.8626 7.46392 19.1997 6.47177 18.364 5.63604C17.5282 4.80031 16.5361 4.13738 15.4442 3.68508C14.3522 3.23279 13.1819 3 12 3C10.8181 3 9.64778 3.23279 8.55585 3.68508C7.46392 4.13738 6.47177 4.80031 5.63604 5.63604C4.80031 6.47177 4.13738 7.46392 3.68508 8.55585C3.23279 9.64778 3 10.8181 3 12ZM9 10C9 10.7956 9.31607 11.5587 9.87868 12.1213C10.4413 12.6839 11.2044 13 12 13C12.7956 13 13.5587 12.6839 14.1213 12.1213C14.6839 11.5587 15 10.7956 15 10C15 9.20435 14.6839 8.44129 14.1213 7.87868C13.5587 7.31607 12.7956 7 12 7C11.2044 7 10.4413 7.31607 9.87868 7.87868C9.31607 8.44129 9 9.20435 9 10Z"
                  stroke="black"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            }
            label="Account Details"
            onPress={() => handleMenuPress('AccountDetails')}
          />

          <SettingsMenuItem
            icon={
              <Svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                <Path
                  d="M1.6001 7H18.4001M1.6001 13H18.4001M9.50016 1C7.8155 3.69961 6.92236 6.81787 6.92236 10C6.92236 13.1821 7.8155 16.3004 9.50016 19M10.5 1C12.1847 3.69961 13.0778 6.81787 13.0778 10C13.0778 13.1821 12.1847 16.3004 10.5 19M1 10C1 11.1819 1.23279 12.3522 1.68508 13.4442C2.13738 14.5361 2.80031 15.5282 3.63604 16.364C4.47177 17.1997 5.46392 17.8626 6.55585 18.3149C7.64778 18.7672 8.8181 19 10 19C11.1819 19 12.3522 18.7672 13.4442 18.3149C14.5361 17.8626 15.5282 17.1997 16.364 16.364C17.1997 15.5282 17.8626 14.5361 18.3149 13.4442C18.7672 12.3522 19 11.1819 19 10C19 7.61305 18.0518 5.32387 16.364 3.63604C14.6761 1.94821 12.3869 1 10 1C7.61305 1 5.32387 1.94821 3.63604 3.63604C1.94821 5.32387 1 7.61305 1 10Z"
                  stroke="black"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            }
            label="Translation Preferences"
            onPress={() => handleMenuPress('TranslationPreferences')}
          />

          <SettingsMenuItem
            icon={
              <Svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                <Path
                  d="M8 11V7C8 5.93913 8.42143 4.92172 9.17157 4.17157C9.92172 3.42143 10.9391 3 12 3C13.0609 3 14.0783 3.42143 14.8284 4.17157C15.5786 4.92172 16 5.93913 16 7V11M5 13C5 12.4696 5.21071 11.9609 5.58579 11.5858C5.96086 11.2107 6.46957 11 7 11H17C17.5304 11 18.0391 11.2107 18.4142 11.5858C18.7893 11.9609 19 12.4696 19 13V19C19 19.5304 18.7893 20.0391 18.4142 20.4142C18.0391 20.7893 17.5304 21 17 21H7C6.46957 21 5.96086 20.7893 5.58579 20.4142C5.21071 20.0391 5 19.5304 5 19V13ZM11 16C11 16.2652 11.1054 16.5196 11.2929 16.7071C11.4804 16.8946 11.7348 17 12 17C12.2652 17 12.5196 16.8946 12.7071 16.7071C12.8946 16.5196 13 16.2652 13 16C13 15.7348 12.8946 15.4804 12.7071 15.2929C12.5196 15.1054 12.2652 15 12 15C11.7348 15 11.4804 15.1054 11.2929 15.2929C11.1054 15.4804 11 15.7348 11 16Z"
                  stroke="black"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            }
            label="Privacy & Security"
            onPress={() => handleMenuPress('PrivacySecurity')}
          />

          <SettingsMenuItem
            icon={
              <Svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                <Path
                  d="M12 8C12.2761 8 12.5 7.77614 12.5 7.5C12.5 7.22386 12.2761 7 12 7C11.7239 7 11.5 7.22386 11.5 7.5C11.5 7.77614 11.7239 8 12 8Z"
                  fill="black"
                />
                <Path
                  d="M10 16.5L12 13.5M12 13.5L14 16.5M12 13.5V11.5M12 11.5L15 10.5M12 11.5L9 10.5M3 12C3 13.1819 3.23279 14.3522 3.68508 15.4442C4.13738 16.5361 4.80031 17.5282 5.63604 18.364C6.47177 19.1997 7.46392 19.8626 8.55585 20.3149C9.64778 20.7672 10.8181 21 12 21C13.1819 21 14.3522 20.7672 15.4442 20.3149C16.5361 19.8626 17.5282 19.1997 18.364 18.364C19.1997 17.5282 19.8626 16.5361 20.3149 15.4442C20.7672 14.3522 21 13.1819 21 12C21 10.8181 20.7672 9.64778 20.3149 8.55585C19.8626 7.46392 19.1997 6.47177 18.364 5.63604C17.5282 4.80031 16.5361 4.13738 15.4442 3.68508C14.3522 3.23279 13.1819 3 12 3C10.8181 3 9.64778 3.23279 8.55585 3.68508C7.46392 4.13738 6.47177 4.80031 5.63604 5.63604C4.80031 6.47177 4.13738 7.46392 3.68508 8.55585C3.23279 9.64778 3 10.8181 3 12ZM12.5 7.5C12.5 7.77614 12.2761 8 12 8C11.7239 8 11.5 7.77614 11.5 7.5C11.5 7.22386 11.7239 7 12 7C12.2761 7 12.5 7.22386 12.5 7.5Z"
                  stroke="black"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            }
            label="App & device"
            onPress={() => handleMenuPress('AppDevice')}
          />

          <SettingsMenuItem
            icon={
              <Svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                <Path
                  d="M12 4L3 9L12 14L21 9L12 4Z"
                  stroke="black"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <Path
                  d="M3 14L12 19L21 14"
                  stroke="black"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <Path
                  d="M3 9.5L12 14.5L21 9.5"
                  stroke="black"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            }
            label="Subscriptions"
            onPress={() => handleMenuPress('Subscriptions')}
          />

          <SettingsMenuItem
            icon={
              <Svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                <Path
                  d="M14 3V7C14 7.26522 14.1054 7.51957 14.2929 7.70711C14.4804 7.89464 14.7348 8 15 8H19M14 3H7C6.46957 3 5.96086 3.21071 5.58579 3.58579C5.21071 3.96086 5 4.46957 5 5V19C5 19.5304 5.21071 20.0391 5.58579 20.4142C5.96086 20.7893 6.46957 21 7 21H17C17.5304 21 18.0391 20.7893 18.4142 20.4142C18.7893 20.0391 19 19.5304 19 19V8M14 3L19 8"
                  stroke="black"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            }
            label="Legal Information"
            onPress={() => handleMenuPress('LegalInformation')}
          />
        </View>
      </ScrollView>

      {/* Background signature */}
      <View style={styles.signatureContainer}>
        <Text style={styles.signature}></Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
  },
  scrollContent: {
    paddingBottom: 100,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 8,
    paddingTop: 44,
    paddingHorizontal: 20,
    paddingBottom: 4,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '600',
    color: '#0C0D11',
    fontFamily: 'Poppins',
  },
  menuContainer: {
  },
  menuItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 16,
    paddingHorizontal: 20,
  },
  menuItemLeft: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  menuItemLabel: {
    fontSize: 16,
    fontWeight: '500',
    color: '#2C2C2C',
    fontFamily: 'Poppins',
    marginLeft: 16,
  },
  signatureContainer: {
    position: 'absolute',
    right: 24,
    bottom: 20,
  },
  signature: {
    fontSize: 40,
    color: '#d1cfd7',
    opacity: 0.7,
    fontFamily: 'Poppins',
  },
  // Styles for the back button
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