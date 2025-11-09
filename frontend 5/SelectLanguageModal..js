import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity, ScrollView } from 'react-native';
import { Svg, Path, Line } from 'react-native-svg';

// --- Reusable Components ---
// Component for the Download Icon
function DownloadIcon() {
    return (
        <View style={styles.downloadIconContainer}>
            <Svg width="16" height="18" viewBox="0 0 16 18" fill="none">
                <Path d="M14.6892 6.49268H10.9392V0.867676H5.31421V6.49268H1.56421L8.12671 13.9927L14.6892 6.49268ZM0.626709 15.8677H15.6267V17.7427H0.626709V15.8677Z" fill="#5E5E5E"/>
            </Svg>
        </View>
    );
}

// Component for a single language option in the list
function LanguageOption({ name, showDownload = true }) {
    return (
        <TouchableOpacity style={styles.languageOptionFrame}>
            <Text style={styles.languageOptionText}>
                {name}
            </Text>
            {showDownload && <DownloadIcon />}
        </TouchableOpacity>
    );
}

// --- Data for Languages (extended for better demo) ---
const recentLanguages = ['English', 'Hindi'];
const allLanguages = [
    'Abkhaz', 'Afrikaans', 'Akan', 'Albanian', 'Amharic', 'Arabic',
    'Armenian', 'Assamese', 'Aymara', 'Azerbaijani', 'Bambara', 'Bashkir',
    'Basque', 'Belarusian', 'Bengali', 'Bhojpuri', 'Bosnian', 'Bulgarian',
    'Burmese', 'Catalan', 'Cebuano', 'Chechen', 'Chichewa', 'Chinese (Mandarin)',
    'Corsican', 'Croatian', 'Czech', 'Danish', 'Divehi', 'Dutch', 'Dzongkha',
    'Esperanto', 'Estonian', 'Ewe', 'Faroese', 'Fijian', 'Finnish', 'French',
    'Frisian', 'Fula', 'Galician', 'Ganda', 'Georgian', 'German', 'Greek',
    'Guarani', 'Gujarati', 'Haitian Creole', 'Hausa', 'Hebrew', 'Herero', 'Hiri Motu',
    'Hungarian', 'Icelandic', 'Igbo', 'Indonesian', 'Interlingua', 'Interlingue',
    'Inuktitut', 'Inupiak', 'Irish', 'Italian', 'Japanese', 'Javanese', 'Kalaallisut',
    'Kannada', 'Kanuri', 'Kashmiri', 'Kazakh', 'Khmer', 'Kikuyu', 'Kinyarwanda',
    'Kirundi', 'Komi', 'Kongo', 'Korean', 'Kwanyama', 'Kyrgyz', 'Lao', 'Latin',
    'Latvian', 'Limburgan', 'Lingala', 'Lithuanian', 'Luba-Katanga', 'Luxembourgish',
    'Macedonian', 'Malagasy', 'Malay', 'Malayalam', 'Maltese', 'Manx', 'Maori',
    'Marathi', 'Marshallese', 'Moldavian', 'Mongolian', 'Nauru', 'Navajo', 'Ndonga',
    'Nepali', 'North Ndebele', 'Northern Sami', 'Norwegian', 'Norwegian Bokmål',
    'Norwegian Nynorsk', 'Nuosu', 'Occitan', 'Ojibwa', 'Oriya', 'Oromo', 'Ossetian',
    'Pali', 'Pashto', 'Persian', 'Polish', 'Portuguese', 'Punjabi', 'Quechua',
    'Romanian', 'Romansh', 'Rundi', 'Russian', 'Sami', 'Samoan', 'Sango', 'Sanskrit',
    'Sardinian', 'Serbian', 'Shona', 'Sichuan Yi', 'Sindhi', 'Sinhala', 'Slovak',
    'Slovenian', 'Somali', 'South Ndebele', 'Southern Sotho', 'Spanish', 'Sundanese',
    'Swahili', 'Swati', 'Swedish', 'Tagalog', 'Tahitian', 'Tajik', 'Tamil', 'Tatar',
    'Telugu', 'Thai', 'Tibetan', 'Tigrinya', 'Tonga', 'Tsonga', 'Tswana', 'Turkish',
    'Turkmen', 'Twi', 'Uighur', 'Ukrainian', 'Urdu', 'Uzbek', 'Venda', 'Vietnamese',
    'Volapük', 'Walloon', 'Welsh', 'Western Frisian', 'Wolof', 'Xhosa', 'Yiddish',
    'Yoruba', 'Zhuang', 'Zulu',
];

// --- Main SelectLanguagemodal Component ---
export default function SelectLanguagemodal() {
    return (
        <View style={styles.selectLanguagemodalContainer}>
            {/* Drag Handle - Adjusted position */}
            <View style={styles.drag}>
                <Svg width="90" height="1" viewBox="0 0 90 1" fill="none">
                    <Line y1="0.5" x2="90" y2="0.5" stroke="#4A4A4A"/>
                </Svg>
            </View>

            {/* Header: Detect Language & Star Icon */}
            <View style={styles.headerFrame}>
                <Text style={styles.detectLanguageText}>
                    {`Detect Language`}
                </Text>
                <View style={styles.starIconContainer}>
                    <Svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                        <Path fillRule="evenodd" clipRule="evenodd" d="M21.375 11.5156C17.015 10.3916 13.608 6.98456 12.484 2.62456L12 0.747559L11.516 2.62456C10.392 6.98456 6.98505 10.3916 2.62505 11.5156L0.748047 11.9996L2.62505 12.4846C6.98505 13.6086 10.392 17.0156 11.516 21.3746L12 23.2526L12.484 21.3746C13.608 17.0156 17.015 13.6086 21.375 12.4846L23.252 11.9996L21.375 11.5156Z" fill="#F6F6F8"/>
                        <Path fillRule="evenodd" clipRule="evenodd" d="M18.7511 7.74697C18.7511 6.58497 20.0251 5.24797 21.2501 5.24797C20.0711 5.24797 18.7511 3.89697 18.7511 2.74997C18.7511 3.89697 17.4431 5.24797 16.2531 5.24797C17.3981 5.24797 18.7511 6.57797 18.7511 7.74697Z" fill="#F6F6F8"/>
                    </Svg>
                </View>
            </View>

            {/* Language Lists - Using ScrollView for the content that might overflow */}
            <ScrollView style={styles.languageListsScrollView}>
                <View style={styles.languageListsInnerContainer}>
                    {/* Recent Languages */}
                    <View style={styles.languageSection}>
                        <Text style={styles.sectionHeader}>
                            {`Recent`}
                        </Text>
                        <View style={styles.optionsList}>
                            {recentLanguages.map(lang => (
                                <LanguageOption key={lang} name={lang} showDownload={false} />
                            ))}
                        </View>
                    </View>

                    {/* All Languages */}
                    <View style={styles.languageSection}>
                        <Text style={styles.sectionHeader}>
                            {`All Languages`}
                        </Text>
                        <View style={styles.optionsList}>
                            {allLanguages.map(lang => (
                                <LanguageOption key={lang} name={lang} showDownload={true} />
                            ))}
                        </View>
                    </View>
                </View>
            </ScrollView>
        </View>
    );
}

const styles = StyleSheet.create({
    selectLanguagemodalContainer: {
        position: "absolute",
        bottom: 0,
        left: 0,
        right: 0,
        width: '100%',
        height: '80%',
        paddingTop: 36,
        borderTopLeftRadius: 20,
        borderTopRightRadius: 20,
        // Changed opacity from 0.4 to 0.7 for a stronger obscuring effect
        backgroundColor: "rgba(36, 36, 36, 0.7)",
        flexDirection: "column",
        alignItems: "flex-start",
    },

    // --- Drag Handle ---
    drag: {
        position: "absolute",
        top: 16,
        left: '50%',
        marginLeft: -45,
        width: 90,
        alignItems: "center",
        justifyContent: 'center',
    },

    // --- Header Section ---
    headerFrame: {
        alignSelf: "stretch",
        flexDirection: "row",
        alignItems: "center",
        justifyContent: "space-between",
        paddingHorizontal: 32,
        paddingVertical: 8,
        marginBottom: 24,
    },

    detectLanguageText: {
        textAlign: "left",
        color: "rgba(255, 255, 255, 1)",
        fontFamily: "Cabinet Grotesk",
        fontSize: 18,
        fontWeight: '500',
        lineHeight: 20.7,
    },

    starIconContainer: {
        height: 24,
        width: 24,
        alignItems: "center",
        justifyContent: "center",
    },

    // --- Language Lists Sections ---
    languageListsScrollView: {
        flex: 1,
        width: '100%',
    },

    languageListsInnerContainer: {
        paddingBottom: 40,
    },

    languageSection: {
        width: '100%',
        flexDirection: "column",
        alignItems: "flex-start",
        rowGap: 12,
        paddingHorizontal: 32,
        marginBottom: 32,
    },

    sectionHeader: {
        alignSelf: "stretch",
        textAlign: "left",
        color: "rgba(162, 160, 162, 1)",
        fontFamily: "Poppins",
        fontSize: 13,
        fontWeight: '400',
        lineHeight: 15,
    },

    optionsList: {
        alignSelf: "stretch",
        flexDirection: "column",
        alignItems: "flex-start",
        rowGap: 4,
    },

    languageOptionFrame: {
        alignSelf: "stretch",
        flexDirection: "row",
        alignItems: "center",
        justifyContent: "space-between",
        paddingVertical: 12,
    },

    languageOptionText: {
        textAlign: "left",
        color: "rgba(255, 255, 255, 1)",
        fontFamily: "Cabinet Grotesk",
        fontSize: 18,
        fontWeight: '500',
        lineHeight: 23.4,
    },

    // --- Download Icon (Reusable) ---
    downloadIconContainer: {
        height: 24,
        width: 24,
        alignItems: "center",
        justifyContent: "center",
    },
});