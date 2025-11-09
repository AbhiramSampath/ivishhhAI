import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  Image,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  TextInput,
  Platform,
  ImageBackground,
} from 'react-native';
import Svg, { Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';
import { getUserDetails } from './api';

// MenuItem as provided
const MenuItem = ({ icon, label, onPress, highlighted, red, hideArrow }) => (
  <TouchableOpacity
    style={[
      styles.listItem,
      highlighted && styles.listItemHighlighted,
      red && styles.listItemRed,
    ]}
    activeOpacity={0.7}
    onPress={onPress}
  >
    {icon}
    <Text
      style={[
        styles.listItemLabel,
        highlighted && styles.listItemLabelHighlighted,
        red && styles.listItemLabelRed,
      ]}
    >
      {label}
    </Text>
    {!hideArrow && (
      <Svg width="8" height="20" viewBox="0 0 8 15" fill="none" style={styles.arrow}>
        <Path
          d="M1.04 13.28L7.04 7.28L1.04 1.28"
          stroke={red ? '#FF4B4B' : 'black'}
          strokeWidth="1.7"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </Svg>
    )}
  </TouchableOpacity>
);

export default function Profile() {
  const navigation = useNavigation();
  const [editMode, setEditMode] = useState(false);

  // Profile details states
  const [name, setName] = useState('Blair Overt');
  const [phone, setPhone] = useState('+91 7649274839');
  const [language, setLanguage] = useState('English');

  useEffect(() => {
    const fetchUserDetails = async () => {
      try {
        const userData = await getUserDetails();
        setName(userData.name || 'Blair Overt');
        setPhone(userData.phone || '+91 7649274839');
        setLanguage(userData.language || 'English');
      } catch (error) {
        console.error('Failed to fetch user details:', error);
      }
    };
    fetchUserDetails();
  }, []);

  // --- EDIT MODE UI (Personal Details screen as in image) ---
  if (editMode) {
    return (
      <View style={styles.detailsContainer}>
        <View style={styles.editTopBar}>
          <TouchableOpacity onPress={() => setEditMode(false)}>
            <Svg width={8} height={24} viewBox="0 0 8 14" fill="none">
              <Path
                d="M7 1L1 7L7 13"
                stroke="black"
                strokeWidth="1.7"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </Svg>
          </TouchableOpacity>
          <Text style={styles.detailsTitle}>Personal Details</Text>
          <TouchableOpacity onPress={() => setEditMode(false)}>
            <Svg width={24} height={24} viewBox="0 0 23 18" fill="none">
              <Path
                d="M8 13.379L3.06 8.44L0.94 10.56L8 17.621L22.56 3.06L20.44 0.94L8 13.379Z"
                fill="#5E5E5E"
              />
            </Svg>
          </TouchableOpacity>
        </View>
        <ScrollView contentContainerStyle={{ paddingBottom: 28 }}>
          <View style={styles.detailsImageContainer}>
            <Image
              source={{ uri: 'https://dummyimage.com/92x92/000/fff.png' }}
              style={styles.detailsImage}
            />
            <TouchableOpacity style={styles.cameraIcon}>
              <Svg width={24} height={24} viewBox="0 0 17 16" fill="none">
                <Path
                  d="M2.796 3.833H3.611C4.043 3.833 4.458 3.657 4.763 3.345C5.069 3.032 5.241 2.608 5.241 2.166C5.241 1.945 5.327 1.733 5.479 1.577C5.632 1.421 5.839 1.333 6.056 1.333H10.944C11.16 1.333 11.368 1.421 11.521 1.577C11.673 1.733 11.759 1.945 11.759 2.166C11.759 2.608 11.931 3.032 12.237 3.345C12.542 3.657 12.957 3.833 13.389 3.833H14.204C14.636 3.833 15.05 4.009 15.356 4.321C15.662 4.634 15.833 5.058 15.833 5.5V13C15.833 13.442 15.662 13.866 15.356 14.178C15.05 14.491 14.636 14.666 14.204 14.666H2.796C2.364 14.666 1.95 14.491 1.644 14.178C1.338 13.866 1.167 13.442 1.167 13V5.5C1.167 5.058 1.338 4.634 1.644 4.321C1.95 4.009 2.364 3.833 2.796 3.833Z"
                  stroke="#787878"
                  strokeWidth="1.33333"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            </TouchableOpacity>
          </View>
          <View style={styles.detailsInputBox}>
            <TextInput
              placeholder="Name"
              value={name}
              onChangeText={setName}
              style={styles.detailsInput}
            />
          </View>
          <Text style={styles.detailsLabel}>Phone Number</Text>
          <View style={styles.detailsInputBox}>
            <TextInput
              placeholder="+91 7649274839"
              value={phone}
              onChangeText={setPhone}
              style={styles.detailsInput}
              keyboardType="phone-pad"
            />
          </View>
          <Text style={styles.detailsLabel}>Default Language</Text>
          <TouchableOpacity style={styles.detailsLanguageBox}>
            <ImageBackground
              style={styles.detailsFlagIcon}
              source={{ uri: 'https://dummyimage.com/24x24/000/fff.png' }}
            />
            <Text style={styles.detailsLanguageText}>{language}</Text>
            <Svg width={8} height={14} viewBox="0 0 8 14" fill="none">
              <Path
                d="M1.04 13L7.04 7L1.04 1"
                stroke="#4A4A4A"
                strokeWidth="1.7"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </Svg>
          </TouchableOpacity>
        </ScrollView>
        <View style={{ position: 'absolute', right: 24, bottom: 20 }}>
          <Text style={{ fontFamily: 'Cabinet Grotesk', fontSize: 40, color: '#d1cfd7', opacity: 0.7 }}>L</Text>
        </View>
      </View>
    );
  }

  // --- PROFILE SCREEN UI (with menu items) -----
  return (
    <View style={styles.profileContainer}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <View style={styles.statusBar} />
        <View style={styles.navigationBar}>
          <TouchableOpacity onPress={() => navigation.goBack()}>
            <Svg width="8" height="24" viewBox="0 0 8 14" fill="none">
              <Path
                d="M7 1L1 7L7 13"
                stroke="black"
                strokeWidth="1.7"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </Svg>
          </TouchableOpacity>
          <Text style={styles.profileTitle}>Profile</Text>
          <View style={{ width: 24 }} />
        </View>
        <View style={styles.profileBox}>
          <Image
            source={{ uri: 'https://dummyimage.com/60x60/000/fff.png' }}
            style={styles.avatar}
          />
          <View style={styles.profileInfo}>
            <Text style={styles.profileName}>{name}</Text>
            <Text style={styles.profileSubtext}>{language}</Text>
          </View>
          <TouchableOpacity style={styles.editButton} onPress={() => setEditMode(true)}>
            <Text style={styles.editButtonText}>Edit</Text>
          </TouchableOpacity>
        </View>
        {/* MENU ITEMS FROM ORIGINAL PROFILE */}
        <View style={styles.settingsList}>
          <MenuItem
            icon={
              <Svg width="24" height="25" viewBox="0 0 24 25" fill="none">
                <Path d="M15.5962 12.2817V6.88748C15.5962 4.89432 13.9914 3.27246 12.0189 3.27246C11.9557 3.27284 11.8926 3.28038 11.831 3.29494C10.908 3.33969 10.0374 3.73758 9.3995 4.40628C8.76159 5.07498 8.40515 5.96331 8.40393 6.88748V12.2817C8.40393 14.265 10.0168 15.8778 12.0001 15.8778C13.9833 15.8778 15.5962 14.265 15.5962 12.2817ZM10.202 12.2817V6.88748C10.202 5.89584 11.0084 5.08941 12.0001 5.08941C12.0492 5.08943 12.0983 5.08491 12.1466 5.07592C13.0681 5.14335 13.7981 5.93001 13.7981 6.88748V12.2817C13.7981 13.2733 12.9917 14.0798 12.0001 14.0798C11.0084 14.0798 10.202 13.2733 10.202 12.2817Z" fill="#2C2C2C"/>
                <Path d="M6.60569 12.2822H4.80762C4.80762 15.9431 7.55956 18.9674 11.1009 19.4125V21.2726H12.8989V19.4125C16.4402 18.9674 19.1922 15.944 19.1922 12.2822H17.3941C17.3941 15.2571 14.9748 17.6764 11.9999 17.6764C9.02499 17.6764 6.60569 15.2571 6.60569 12.2822Z" fill="#2C2C2C"/>
              </Svg>
            }
            label="Voice Settings"
            onPress={() => navigation.navigate("VoiceSettings")}
          />
          <MenuItem
            icon={
              <Svg width="24" height="25" viewBox="0 0 24 25" fill="none">
                <Path
                  d="M18.3 7.69894C18.575 7.85531 18.8033 8.08212 18.9615 8.35603C19.1197 8.62994 19.202 8.94106 19.2001 9.25736V15.0847C19.2001 15.7319 18.8457 16.3287 18.2736 16.6431L12.8735 20.0592C12.6058 20.2061 12.3053 20.2832 11.9999 20.2832C11.6945 20.2832 11.394 20.2061 11.1263 20.0592L5.72622 16.6431C5.44635 16.4901 5.21271 16.2648 5.04974 15.9907C4.88677 15.7165 4.80045 15.4036 4.7998 15.0847V9.25656C4.7998 8.60935 5.15421 8.01334 5.72622 7.69894L11.1263 4.51488C11.402 4.36291 11.7116 4.2832 12.0263 4.2832C12.3411 4.2832 12.6507 4.36291 12.9263 4.51488L18.3264 7.69894H18.3Z"
                  stroke="#2C2C2C"
                  strokeWidth={1.7}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <Path
                  d="M9.59989 12.2833C9.59989 12.9199 9.85275 13.5303 10.3028 13.9804C10.7529 14.4305 11.3634 14.6834 11.9999 14.6834C12.6365 14.6834 13.2469 14.4305 13.697 13.9804C14.1471 13.5303 14.4 12.9199 14.4 12.2833C14.4 11.6468 14.1471 11.0364 13.697 10.5863C13.2469 10.1362 12.6365 9.8833 11.9999 9.8833C11.3634 9.8833 10.7529 10.1362 10.3028 10.5863C9.85275 11.0364 9.59989 11.6468 9.59989 12.2833Z"
                  stroke="#2C2C2C"
                  strokeWidth={1.7}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            }
            label="Settings"
            onPress={() => navigation.navigate("Settings")}
          />
          <MenuItem
            icon={
              <Svg width="24" height="25" viewBox="0 0 24 25" fill="none">
                <Path
                  d="M12 4.5L3 10.5L12 21.2L21 10.5L12 4.5Z"
                  stroke="#2C2C2C"
                  strokeWidth="1.7"
                  fill="#bfc5f5"
                />
                <Path
                  d="M12 4.5V21.2M12 4.5L3 10.5M12 4.5L21 10.5M3 10.5L12 21.2M21 10.5L12 21.2"
                  stroke="#2C2C2C"
                  strokeWidth="1.2"
                />
              </Svg>
            }
            label="Premium"
            highlighted
            onPress={() => navigation.navigate("Premium")}
          />
          <MenuItem
            icon={
              <Svg width="24" height="25" viewBox="0 0 24 25" fill="none">
                <Path
                  d="M12 6.2832C12 6.81364 12.2107 7.32234 12.5858 7.69742C12.9609 8.07249 13.4696 8.2832 14 8.2832C14.5304 8.2832 15.0391 8.07249 15.4142 7.69742C15.7893 7.32234 16 6.81364 16 6.2832M12 6.2832C12 5.75277 12.2107 5.24406 12.5858 4.86899C12.9609 4.49392 13.4696 4.2832 14 4.2832C14.5304 4.2832 15.0391 4.49392 15.4142 4.86899C15.7893 5.24406 16 5.75277 16 6.2832M12 6.2832H4M16 6.2832H20M6 12.2832C6 12.8136 6.21071 13.3223 6.58579 13.6974C6.96086 14.0725 7.46957 14.2832 8 14.2832C8.53043 14.2832 9.03914 14.0725 9.41421 13.6974C9.78929 13.3223 10 12.8136 10 12.2832M6 12.2832C6 11.7528 6.21071 11.2441 6.58579 10.869C6.96086 10.4939 7.46957 10.2832 8 10.2832C8.53043 10.2832 9.03914 10.4939 9.41421 10.869C9.78929 11.2441 10 11.7528 10 12.2832M6 12.2832H4M10 12.2832H20M15 18.2832C15 18.8136 15.2107 19.3223 15.5858 19.6974C15.9609 20.0725 16.4696 20.2832 17 20.2832C17.5304 20.2832 18.0391 20.0725 18.4142 19.6974C18.7893 19.3223 19 18.8136 19 18.2832M15 18.2832C15 17.7528 15.2107 17.2441 15.5858 16.869C15.9609 16.4939 16.4696 16.2832 17 16.2832C17.5304 16.2832 18.0391 16.4939 18.4142 16.869C18.7893 17.2441 19 17.7528 19 18.2832M15 18.2832H4M19 18.2832H20"
                  stroke="#2C2C2C"
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            }
            label="Personalization & Memory"
            onPress={() => navigation.navigate("Personalisation")}
          />
          <MenuItem
            icon={
              <Svg width="24" height="25" viewBox="0 0 24 25" fill="none">
                <Path
                  d="M12 15.4623C12.2267 15.4623 12.4168 15.3798 12.5704 15.2146C12.724 15.0495 12.8005 14.8455 12.8 14.6024C12.7995 14.3593 12.7227 14.1552 12.5696 13.9901C12.4165 13.825 12.2267 13.7424 12 13.7424C11.7733 13.7424 11.5835 13.825 11.4304 13.9901C11.2773 14.1552 11.2005 14.3593 11.2 14.6024C11.1995 14.8455 11.2763 15.0498 11.4304 15.2155C11.5845 15.3812 11.7744 15.4635 12 15.4623ZM12 12.0226C12.2267 12.0226 12.4168 11.94 12.5704 11.7749C12.724 11.6098 12.8005 11.4057 12.8 11.1627V7.72293C12.8 7.47928 12.7232 7.27519 12.5696 7.11066C12.416 6.94612 12.2261 6.86357 12 6.863C11.7739 6.86242 11.584 6.94498 11.4304 7.11066C11.2768 7.27634 11.2 7.48043 11.2 7.72293V11.1627C11.2 11.4063 11.2768 11.6107 11.4304 11.7758C11.584 11.9409 11.7739 12.0232 12 12.0226ZM7.2 18.0421L5.36 20.0199C5.10667 20.2923 4.81653 20.3533 4.4896 20.2031C4.16267 20.0529 3.99947 19.784 4 19.3965V6.00307C4 5.5301 4.1568 5.12536 4.4704 4.78884C4.784 4.45232 5.16053 4.28378 5.6 4.2832H18.4C18.84 4.2832 19.2168 4.45175 19.5304 4.78884C19.844 5.12594 20.0005 5.53068 20 6.00307V16.3222C20 16.7952 19.8435 17.2002 19.5304 17.5373C19.2173 17.8744 18.8405 18.0427 18.4 18.0421H7.2ZM6.52 16.3222H18.4V6.00307H5.6V17.2897L6.52 16.3222Z"
                  fill="#2C2C2C"
                />
              </Svg>
            }
            label="Help and Feedback"
            onPress={() => navigation.navigate("HelpAndFeedback")}
          />
          <MenuItem
            icon={
              <Svg width="24" height="25" viewBox="0 0 24 25" fill="none">
                <Path
                  d="M8 18.5713H16C16.1572 18.5713 16.2656 18.6191 16.3594 18.7129C16.453 18.8066 16.5004 18.9146 16.5 19.0703C16.4996 19.2271 16.4517 19.3366 16.3574 19.4316C16.265 19.5247 16.1578 19.572 16.002 19.5713H8C7.84287 19.5713 7.73546 19.5229 7.64258 19.4297C7.5488 19.3356 7.50045 19.2271 7.5 19.0703C7.49963 18.9151 7.54645 18.8067 7.64062 18.7129C7.73579 18.6181 7.8449 18.5713 8 18.5713ZM12.0029 4.99609C12.0809 4.99575 12.1464 5.00761 12.2031 5.02832C12.2442 5.04334 12.293 5.07208 12.3486 5.12695L15.9463 8.72461C16.0337 8.81204 16.0829 8.91824 16.0879 9.0752C16.092 9.20764 16.0525 9.31152 15.9473 9.41602L15.9463 9.41797C15.8659 9.4982 15.7637 9.5459 15.5996 9.5459C15.4358 9.54582 15.3342 9.49808 15.2539 9.41797L15.251 9.41504L13.3516 7.54004L12.5 6.7002V15.0713C12.5 15.2289 12.4517 15.338 12.3584 15.4316C12.2662 15.524 12.1585 15.5717 12.001 15.5713H12C11.8429 15.5713 11.7355 15.5229 11.6426 15.4297C11.5723 15.3591 11.5269 15.2808 11.5088 15.1797L11.5 15.0703V6.7002L10.6484 7.54004L8.74902 9.41504L8.74609 9.41797C8.65854 9.50536 8.55306 9.55462 8.39746 9.55957C8.26594 9.56372 8.16025 9.52439 8.05371 9.41797C7.97334 9.3376 7.92484 9.23545 7.9248 9.07129C7.9248 8.90702 7.97331 8.80501 8.05371 8.72461L11.6533 5.125C11.7082 5.07013 11.7549 5.04342 11.792 5.03027C11.8519 5.00906 11.9213 4.9965 12.0029 4.99609Z"
                  stroke="#2C2C2C"
                />
              </Svg>
            }
            label="Update"
            onPress={() => navigation.navigate("Update")}
            hideArrow
          />
          <MenuItem
            icon={
              <Svg width="16" height="17" viewBox="0 0 16 17" fill="none">
                <Path
                  d="M1.60016 3.00327C1.60016 2.70622 1.71816 2.42134 1.92821 2.21129C2.13825 2.00124 2.42314 1.88324 2.72019 1.88324H7.68031C7.97736 1.88324 8.26224 2.00124 8.47229 2.21129C8.68233 2.42134 8.80033 2.70622 8.80033 3.00327V5.08332C8.80033 5.2955 8.88462 5.49898 9.03465 5.64902C9.18469 5.79905 9.38817 5.88334 9.60035 5.88334C9.81253 5.88334 10.016 5.79905 10.1661 5.64902C10.3161 5.49898 10.4004 5.2955 10.4004 5.08332V3.00327C10.4004 2.64606 10.33 2.29236 10.1933 1.96234C10.0566 1.63233 9.85626 1.33247 9.60368 1.07989C9.3511 0.82731 9.05124 0.626952 8.72123 0.490256C8.39122 0.35356 8.03751 0.283203 7.68031 0.283203H2.72019C1.99878 0.283203 1.30692 0.569781 0.796811 1.07989C0.2867 1.59 0.00012207 2.28186 0.00012207 3.00327V13.5635C0.00012207 14.2849 0.2867 14.9768 0.796811 15.4869C1.30692 15.997 1.99878 16.2836 2.72019 16.2836H7.68031C8.40171 16.2836 9.09357 15.997 9.60368 15.4869C10.1138 14.9768 10.4004 14.2849 10.4004 13.5635V11.4835C10.4004 11.2713 10.3161 11.0678 10.1661 10.9178C10.016 10.7677 9.81253 10.6835 9.60035 10.6835C9.38817 10.6835 9.18469 10.7677 9.03465 10.9178C8.88462 11.0678 8.80033 11.2713 8.80033 11.4835V13.5635C8.80033 13.8606 8.68233 14.1455 8.47229 14.3555C8.26224 14.5655 7.97736 14.6835 7.68031 14.6835H2.72019C2.42314 14.6835 2.13825 14.5655 1.92821 14.3555C1.71816 14.1455 1.60016 13.8606 1.60016 13.5635V3.00327Z"
                  fill="#FF4B4B"
                />
                <Path
                  d="M12.2346 5.31724C12.3846 5.16726 12.588 5.08301 12.8002 5.08301C13.0123 5.08301 13.2158 5.16726 13.3658 5.31724L15.7659 7.7173C15.9158 7.86733 16.0001 8.07078 16.0001 8.28291C16.0001 8.49505 15.9158 8.6985 15.7659 8.84853L13.3658 11.2486C13.2149 11.3943 13.0128 11.475 12.8031 11.4731C12.5933 11.4713 12.3926 11.3872 12.2443 11.2388C12.096 11.0905 12.0118 10.8899 12.01 10.6801C12.0082 10.4703 12.0888 10.2682 12.2346 10.1174L13.269 9.08293H3.99997C3.78779 9.08293 3.5843 8.99865 3.43427 8.84861C3.28424 8.69858 3.19995 8.49509 3.19995 8.28291C3.19995 8.07074 3.28424 7.86725 3.43427 7.71722C3.5843 7.56718 3.78779 7.48289 3.99997 7.48289H13.269L12.2346 6.44847C12.0846 6.29844 12.0003 6.09499 12.0003 5.88286C12.0003 5.67072 12.0846 5.46727 12.2346 5.31724Z"
                  fill="#FF4B4B"
                />
              </Svg>
            }
            label="Sign Out"
            red
            onPress={() => navigation.navigate('Splash')} // Corrected navigation target
            hideArrow
          />
        </View>
      </ScrollView>
    </View>
  );
}

// --- STYLES (unchanged plus edit mode additions) ---
const styles = StyleSheet.create({
  // Profile display
  profileContainer: {
    flex: 1,
    backgroundColor: '#fff',
    position: 'relative',
    paddingTop: 34,
  },
  scrollContent: {
    paddingBottom: 24,
  },
  statusBar: {
    height: 0,
    width: '100%',
    backgroundColor: '#fff',
  },
  navigationBar: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    height: 48,
    paddingHorizontal: 20,
    marginTop: 6,
    marginBottom: 12,
    marginLeft:9,
  },
  profileTitle: {
    marginRight:270,
    color: '#0c0d11',
    height:26,
    width:62,
    fontSize: 20,
    fontWeight: '500',
    fontFamily: 'Poppins',
    marginLeft:10,
  },
  profileBox: {
    flexDirection: 'row',
    alignItems: 'center',
    marginHorizontal: 24,
    marginVertical: 14,
    backgroundColor: '#fff',
    borderRadius: 20,
    padding: 12,
    shadowOffset: { width: 0, height: 2 },
  },
  avatar: {
    width: 60,
    height: 60,
    borderRadius: 30,
    marginRight: 15,
  },
  profileInfo: {
    flex: 1,
    justifyContent: 'center',
  },
  profileName: {
    color: '#2c2c2c',
    fontSize: 24,
    fontWeight: '500',
    fontFamily: 'Cabinet Grotesk',
  },
  profileSubtext: {
    color: '#2c2c2c',
    fontFamily: 'Poppins',
    fontSize: 12,
    fontWeight: '400',
    marginTop: 2,
  },
  editButton: {
    backgroundColor: '#f6f6f8',
    paddingVertical: 6,
    paddingHorizontal: 18,
    borderRadius: 12,
    marginLeft: 10,
    height:43,
  },
  editButtonText: {
    color: '#2c2c2c',
    fontFamily: 'Inter',
    fontSize: 16,
    marginTop:4,
    fontWeight: '700',
  },
  settingsList: {
    marginTop: 10,
    marginHorizontal: 5,
  },
  listItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#fff',
    borderRadius: 20,
    paddingHorizontal: 20,
    paddingVertical: 16,
    marginVertical: 2,
  },
  listItemHighlighted: {
    backgroundColor: '#bfc5f5',
  },
  listItemRed: {
    backgroundColor: '#fff',
  },
  listItemLabel: {
    flex: 1,
    color: '#2c2c2c',
    fontFamily: 'Poppins',
    fontSize: 16,
    fontWeight: '500',
    marginLeft: 16,
  },
  listItemLabelHighlighted: {
    color: '#2c2c2c',
  },
  listItemLabelRed: {
    color: '#ff4b4b',
  },
  arrow: {
    marginLeft: 8,
  },
  detailsContainer: {
    flex: 1,
    backgroundColor: '#fff',
    paddingHorizontal: 24,
    paddingTop: Platform.OS === 'android' ? 44 : 44,
  },
  editTopBar: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 18,
    marginTop: 8,
    marginLeft: 9,
  },
  detailsTitle: {
    marginRight:180,
    fontSize: 20,
    fontWeight: '500',
    color: '#0c0d11',
    fontFamily: 'Poppins',
  },
  detailsImageContainer: {
    alignItems: 'center',
    marginBottom: 18,
    marginTop: 8,
    position: 'relative',
  },
  detailsImage: {
    width: 92,
    height: 92,
    borderRadius: 46,
  },
  cameraIcon: {
    position: 'absolute',
    right: 0,
    bottom: 0,
    backgroundColor: '#D9D9D9',
    borderRadius: 16,
    padding: 7,
  },
  detailsInputBox: {
    backgroundColor: '#fff',
    borderRadius: 12,
    borderWidth: 1.1,
    borderColor: '#848484',
    marginBottom: 18,
    paddingHorizontal: 12,
    justifyContent: 'center',
    height: 48,
  },
  detailsInput: {
    fontSize: 16,
    color: '#5e5e5e',
    fontFamily: 'Poppins',
  },
  detailsLabel: {
    fontSize: 14,
    color: '#4A4A4A',
    fontFamily: 'Cabinet Grotesk',
    marginBottom: 2,
    marginLeft: 2,
  },
  detailsLanguageBox: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#fff',
    borderRadius: 12,
    borderWidth: 1.1,
    borderColor: '#848484',
    marginBottom: 18,
    paddingHorizontal: 12,
    height: 48,
  },
  detailsFlagIcon: {
    width: 24,
    height: 24,
    marginRight: 8,
  },
  detailsLanguageText: {
    flex: 1,
    color: '#1d1d1f',
    fontSize: 16,
    fontFamily: 'Poppins',
  },
});