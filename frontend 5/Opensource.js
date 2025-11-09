import React, { useState, useRef, useEffect } from 'react';
import { View, Text, StyleSheet, SafeAreaView, TouchableOpacity, ScrollView, Animated } from 'react-native';
import { Svg, Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';
import { getOpenSourceLicenses } from './api';

// Reusable Components
const NavIconsBack = () => (
  <View style={styles.navIconsBackContainer}>
    <Svg width="8" height="14" viewBox="0 0 8 14" fill="none">
      <Path d="M7 1L1 7L7 13" stroke="#2C2C2C" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  </View>
);

const Header = ({ title, onBackPress }) => ( 
  <View style={styles.header}>
    <View style={styles.headerContent}>
      <TouchableOpacity onPress={onBackPress}>
        <NavIconsBack />
      </TouchableOpacity>
      <Text style={styles.headerTitle}>{title}</Text>
    </View>
    <View style={styles.rightIcons}>
      <View style={styles.languageDropdown}>
        <Text style={styles.languageText}>EN</Text>
        <Svg width="10" height="7" viewBox="0 0 10 7" fill="none">
          <Path d="M1 1.5L5 5.5L9 1.5" stroke="#0C0D11" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </Svg>
      </View>
    </View>
  </View>
);

const LicenseSubItem = ({ text, license, icon, isLast }) => (
  <View style={[styles.subItemContainer, !isLast && styles.subItemBorder]}>
    <View>
      <Text style={styles.subItemText}>{text}</Text>
      <Text style={styles.subItemLicense}>{license}</Text>
    </View>
    <View style={styles.subItemIcon}>{icon}</View>
  </View>
);

const DropdownItem = ({ icon, text, children }) => {
  const [isOpen, setIsOpen] = useState(false);
  const animatedHeight = useRef(new Animated.Value(0)).current;
  const contentHeight = useRef(null);

  const toggleDropdown = () => {
    if (isOpen) {
      Animated.timing(animatedHeight, {
        toValue: 0,
        duration: 250,
        useNativeDriver: false,
      }).start(() => setIsOpen(false));
    } else {
      setIsOpen(true);
      Animated.timing(animatedHeight, {
        toValue: contentHeight.current,
        duration: 250,
        useNativeDriver: false,
      }).start();
    }
  };

  const onLayout = (event) => {
    if (contentHeight.current === null) {
      contentHeight.current = event.nativeEvent.layout.height;
      if (isOpen) {
        animatedHeight.setValue(contentHeight.current);
      }
    }
  };

  const childArray = React.Children.toArray(children);

  return (
    <View style={[styles.licensedropdownContainer, isOpen && styles.licensedropdownContainerActive]}>
      <TouchableOpacity style={styles.frame3146} onPress={toggleDropdown}>
        <View style={styles.frame3145}>
          <View style={styles.licenseIconContainer}>
            {icon}
          </View>
          <Text style={styles.placeHolder}>{text}</Text>
        </View>
        <Svg style={[styles.chevronVector, isOpen && { transform: [{ rotate: '180deg' }] }]} width="14" height="8" viewBox="0 0 14 8" fill="none">
          <Path d="M1 1L7 7L13 1" stroke="#0E0E0E" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </Svg>
      </TouchableOpacity>
      <Animated.View style={[styles.dropdownContent, { height: animatedHeight }]}>
        <View onLayout={onLayout} style={{ position: 'absolute', width: '100%', paddingHorizontal: 20, paddingTop: 10 }}>
          {childArray.map((child, index) =>
            React.cloneElement(child, {
              isLast: index === childArray.length - 1
            })
          )}
        </View>
      </Animated.View>
    </View>
  );
};

// Main Screen Component
const OpenSourceLicensesScreen = () => {
  const navigation = useNavigation();
  const [licenses, setLicenses] = useState({
    nlp: [],
    stt: [],
    tts: [],
    security: [],
    ui: []
  });

  useEffect(() => {
    const fetchLicenses = async () => {
      try {
        const data = await getOpenSourceLicenses();
        setLicenses(data);
      } catch (error) {
        console.error('Failed to fetch open source licenses:', error);
      }
    };
    fetchLicenses();
  }, []);

  const nlpIcon = <Svg width="18" height="18" viewBox="0 0 18 18" fill="none"><Path d="M11.9167 9.83333C11.1431 9.83333 10.4013 10.1406 9.85427 10.6876C9.30729 11.2346 9 11.9765 9 12.75M9 12.75V13.5833M9 12.75C9 11.9765 8.69271 11.2346 8.14573 10.6876C7.59875 10.1406 6.85688 9.83333 6.08333 9.83333M9 12.75V4.41667M9 13.5833C9 14.3569 9.30729 15.0987 9.85427 15.6457C10.4013 16.1927 11.1431 16.5 11.9167 16.5C12.6902 16.5 13.4321 16.1927 13.9791 15.6457C14.526 15.0987 14.8333 14.3569 14.8333 13.5833V12.0833M9 13.5833C9 14.3569 8.69271 15.0987 8.14573 15.6457C7.59875 16.1927 6.85688 16.5 6.08333 16.5C5.30979 16.5 4.56792 16.1927 4.02094 15.6457C3.47396 15.0987 3.16667 14.3569 3.16667 13.5833V12.0833M13.5833 12.3333C14.3569 12.3333 15.0987 12.026 15.6457 11.4791C16.1927 10.9321 16.5 10.1902 16.5 9.41667C16.5 8.64312 16.1927 7.90125 15.6457 7.35427C15.0987 6.80729 14.3569 6.5 13.5833 6.5H13.1667M14.8333 6.75V4.41667C14.8333 3.64312 14.526 2.90125 13.9791 2.35427C13.4321 1.80729 12.6902 1.5 11.9167 1.5C11.1431 1.5 10.4013 1.80729 9.85427 2.35427C9.30729 2.90125 9 3.64312 9 4.41667M9 4.41667C9 3.64312 8.69271 2.90125 8.14573 2.35427C7.59875 1.80729 6.85688 1.5 6.08333 1.5C5.30979 1.5 4.56792 1.80729 4.02094 2.35427C3.47396 2.90125 3.16667 3.64312 3.16667 4.41667V6.75M4.41667 12.3333C3.64312 12.3333 2.90125 12.026 2.35427 11.4791C1.80729 10.9321 1.5 10.1902 1.5 9.41667C1.5 8.64312 1.80729 7.90125 2.35427 7.35427C2.90125 6.80729 3.64312 6.5 4.41667 6.5H4.83333" stroke="black" strokeWidth="1.66667" strokeLinecap="round" strokeLinejoin="round"/></Svg>;
  const sttIcon = <Svg width="18" height="18" viewBox="0 0 18 18" fill="none"><Path d="M9 14.25C9.72826 14.25 10.4266 13.9603 10.9393 13.4476C11.452 12.9349 11.7413 12.2365 11.7413 11.5083V3.49169C11.7413 2.76352 11.452 2.06518 10.9393 1.55245C10.4266 1.03972 9.72826 0.75 9 0.75C8.27174 0.75 7.5734 1.03972 7.06066 1.55245C6.54793 2.06518 6.25867 2.76352 6.25867 3.49169V11.5083C6.25867 12.2365 6.54793 12.9349 7.06066 13.4476C7.5734 13.9603 8.27174 14.25 9 14.25Z" stroke="#2C2C2C" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><Path d="M15.75 8.75V11.5083C15.75 12.9377 15.1951 14.3087 14.2185 15.3056C13.242 16.3025 11.8988 16.8523 10.5188 16.8523H7.48126C6.10125 16.8523 4.75806 16.3025 3.78153 15.3056C2.80501 14.3087 2.25008 12.9377 2.25008 11.5083V8.75" stroke="#2C2C2C" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></Svg>
  const ttsIcon = <Svg width="18" height="16" viewBox="0 0 18 16" fill="none"><Path d="M11.5 4.66687C12.0175 5.05498 12.4375 5.55825 12.7268 6.13681C13.0161 6.71538 13.1667 7.35335 13.1667 8.0002C13.1667 8.64706 13.0161 9.28503 12.7268 9.86359C12.4375 10.4422 12.0175 10.9454 11.5 11.3335M13.7502 2.16687C14.6201 2.86991 15.3218 3.75864 15.8039 4.76797C16.2859 5.7773 16.5361 6.88167 16.5361 8.0002C16.5361 9.11874 16.2859 10.2231 15.8039 11.2324C15.3218 12.2418 14.6201 13.1305 13.7502 13.8335M4 10.5002H2.33333C2.11232 10.5002 1.90036 10.4124 1.74408 10.2561C1.5878 10.0998 1.5 9.88786 1.5 9.66685V6.33351C1.5 6.1125 1.5878 5.90054 1.74408 5.74426C1.90036 5.58798 2.11232 5.50018 2.33333 5.50018H4L6.91667 1.75018C6.9895 1.60871 7.11054 1.49795 7.25791 1.43792C7.40528 1.3779 7.56925 1.37256 7.72021 1.42288C7.87117 1.4732 7.99915 1.57586 8.08103 1.7123C8.16291 1.84874 8.19328 2.00997 8.16667 2.16685V13.8335C8.19328 13.9904 8.16291 14.1516 8.08103 14.2881C7.99915 14.4245 7.87117 14.5272 7.72021 14.5775C7.56925 14.6278 7.40528 14.6225 7.25791 14.5624C7.11054 14.5024 6.9895 14.3917 6.91667 14.2502L4 10.5002Z" stroke="black" strokeWidth="1.66667" strokeLinecap="round" strokeLinejoin="round"/></Svg>;

  const securityIcon = <Svg width="18" height="18" viewBox="0 0 18 18" fill="none"><Path d="M9 1.5L15.75 4.5V9C15.75 12.7279 12.7279 15.75 9 15.75C5.27208 15.75 2.25 12.7279 2.25 9V4.5L9 1.5Z" stroke="black" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><Path d="M6.75 8.25L8.25 9.75L12.75 5.25" stroke="black" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></Svg>;
  const uiIcon = <Svg width="18" height="18" viewBox="0 0 18 18" fill="none"><Path d="M1.5 4.5H16.5M1.5 9H16.5M1.5 13.5H16.5M4.5 1.5V7.5M13.5 10.5V16.5" stroke="black" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></Svg>;
  const catIcon = <Svg width="16" height="16" viewBox="0 0 16 16" fill="none"><Path d="M8 1.5C6.61929 1.5 5.5 2.61929 5.5 4C5.5 5.38071 6.61929 6.5 8 6.5C9.38071 6.5 10.5 5.38071 10.5 4C10.5 2.61929 9.38071 1.5 8 1.5Z" stroke="#4A4A4A" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><Path d="M3 10.5C3 8.84315 4.34315 7.5 6 7.5H10C11.6569 7.5 13 8.84315 13 10.5V13.5C13 14.3284 12.3284 15 11.5 15H4.5C3.67157 15 3 14.3284 3 13.5V10.5Z" stroke="#4A4A4A" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></Svg>;
  const docIcon = <Svg width="16" height="16" viewBox="0 0 16 16" fill="none"><Path d="M10.5 2.5H5.5C4.67157 2.5 4 3.17157 4 4V12C4 12.8284 4.67157 13.5 5.5 13.5H10.5C11.3284 13.5 12 12.8284 12 12V5.5L10.5 2.5Z" stroke="#4A4A4A" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><Path d="M10.5 2.5V5.5H12" stroke="#4A4A4A" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><Path d="M6 7.5H10M6 9.5H10M6 11.5H8" stroke="#4A4A4A" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></Svg>;

  return (
    <SafeAreaView style={styles.container}>
      <Header title="Open Source Licenses" onBackPress={() => navigation.goBack()} />
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <DropdownItem
          icon={nlpIcon}
          text="NLP"
        >
          {licenses.nlp.map(item => (
            <LicenseSubItem key={item.text} text={item.text} license={item.license} icon={catIcon} />
          ))}
        </DropdownItem>
        <DropdownItem
          icon={sttIcon}
          text="STT"
        >
          {licenses.stt.map(item => (
            <LicenseSubItem key={item.text} text={item.text} license={item.license} icon={catIcon} />
          ))}
        </DropdownItem>
        <DropdownItem
          icon={ttsIcon}
          text="TTS"
        >
          {licenses.tts.map(item => (
            <LicenseSubItem key={item.text} text={item.text} license={item.license} icon={catIcon} />
          ))}
        </DropdownItem>
        <DropdownItem
          icon={securityIcon}
          text="Security"
        >
          {licenses.security.map(item => (
            <LicenseSubItem key={item.text} text={item.text} license={item.license} icon={catIcon} />
          ))}
        </DropdownItem>
        <DropdownItem
          icon={uiIcon}
          text="UI"
        >
          {licenses.ui.map(item => (
            <LicenseSubItem key={item.text} text={item.text} license={item.license} icon={item.text === 'MongoDB TTL' ? docIcon : catIcon} />
          ))}
        </DropdownItem>
      </ScrollView>
    </SafeAreaView>
  );
};

// Styles
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
  },
  scrollContent: {
    paddingHorizontal: 20,
    paddingBottom: 20,
  },
  // Header Styles
  header: {
    paddingTop: 44,
    paddingHorizontal: 7,
    marginBottom: 20,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginLeft:8,
  },
  headerContent: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 15,
  },
  navIconsBackContainer: {
    height: 36,
    width: 36,
    justifyContent: 'center',
    alignItems: 'center',
  },
  headerTitle: {
    color: '#0C0D11',
    fontSize: 20,
    fontWeight: '500',
  },
  rightIcons: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 15,
    paddingRight: 20,
  },
  languageDropdown: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 5,
  },
  languageText: {
    color: '#0C0D11',
    fontSize: 14,
    fontWeight: '500',
  },
  // Dropdown Item Styles
  licensedropdownContainer: {
    alignSelf: "stretch",
    borderWidth: 1,
    borderColor: "rgba(44, 44, 44, 1)",
    borderRadius: 12,
    marginBottom: 10,
    overflow: 'hidden',
  },
  licensedropdownContainerActive: {
    borderBottomLeftRadius: 0,
    borderBottomRightRadius: 0,
  },
  frame3146: {
    height: 56,
    width: '100%',
    flexDirection: 'row',
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 16,
  },
  frame3145: {
    flexDirection: 'row',
    alignItems: "center",
    columnGap: 8,
  },
  licenseIconContainer: {
    height: 20,
    width: 20,
    justifyContent: 'center',
    alignItems: 'center',
  },
  placeHolder: {
    textAlign: "left",
    color: "rgba(0, 0, 0, 1)",
    fontSize: 14,
    fontWeight: '500',
  },
  chevronVector: {
    transform: [{ rotate: '0deg' }],
  },
  dropdownContent: {
    overflow: 'hidden',
    borderTopWidth: 1,
    borderTopColor: "rgba(44, 44, 44, 1)",
  },
  subItemContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 10,
  },
  subItemBorder: {
    borderBottomWidth: 1,
    borderBottomColor: '#EDEDED',
  },
  subItemText: {
    color: '#0C0D11',
    fontSize: 14,
    fontWeight: '500',
  },
  subItemLicense: {
    color: '#4A4A4A',
    fontSize: 12,
  },
  subItemIcon: {
    width: 24,
    height: 24,
    justifyContent: 'center',
    alignItems: 'center',
  },
});

export default OpenSourceLicensesScreen;